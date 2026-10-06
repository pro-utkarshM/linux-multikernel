#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded extension of the pinned #35/Kerf guest, not a standalone harness."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import subprocess
import sys
import time
import traceback
import tempfile
import threading
from contextlib import contextmanager

BASE = Path('/sys/fs/multikernel')


def wait_retained_harts(execute, read_log, harts, expected_state):
    """Observe via rejected execution; never turn observation into reuse."""
    from verify_retention import hsm_samples

    deadline = time.monotonic() + 20
    last_sample = 0
    while time.monotonic() < deadline:
        require_errno(execute, errno.EBUSY)
        groups = hsm_samples(read_log(), harts)
        assert groups and groups[-1]['sample'] > last_sample, 'missing fresh HSM sample'
        last_sample = groups[-1]['sample']
        if all(state == expected_state for state in groups[-1]['states'].values()):
            return
        time.sleep(0.1)
    raise TimeoutError('retained harts did not reach the required observed state')


def marker(kind, **values):
    print('MK_LIFECYCLE_' + kind + ' ' + json.dumps(values, sort_keys=True), flush=True)


def mount(source, target, kind):
    Path(target).mkdir(parents=True, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    if libc.mount(source.encode(), target.encode(), kind.encode(), 0, None):
        raise OSError(ctypes.get_errno(), target)


def cpu_set(text):
    result = set()
    for item in text.split(','):
        parts = [int(x) for x in item.split('-')]
        result.update(range(parts[0], parts[-1] + 1))
    return result


def connect_console(instance_id):
    fd = os.open('/dev/mktty', os.O_RDWR | os.O_NONBLOCK)
    try:
        selection = (str(instance_id) + '\n').encode()
        assert os.write(fd, selection) == len(selection)
    except Exception:
        os.close(fd)
        raise
    return fd


def drain_console(fd, received, timeout=0):
    # Bound one drain even if a misbehaving child continuously writes.
    for _ in range(64):
        if not select.select([fd], [], [], timeout)[0]:
            return
        data = os.read(fd, 4096)
        assert data, 'console closed early'
        print(data.decode(errors='replace'), end='', flush=True)
        received.extend(data)
        assert b'MK_CHILD_FAIL' not in received
        timeout = 0


def require_errno(operation, expected):
    try:
        operation()
    except OSError as error:
        assert error.errno == expected, repr(error)
        return error.errno
    raise AssertionError('operation unexpectedly succeeded')


def writer_stress(unload):
    """Real guest syscalls and live child replies; no kernel scheduling proof."""
    barrier = threading.Barrier(2, timeout=10)
    windows = [None, None]
    errors = []
    counts = [0, 0]

    def worker(index):
        start = time.monotonic_ns()
        try:
            for iteration in range(64):
                barrier.wait()
                if index == 0:
                    require_errno(unload, errno.EBUSY)
                else:
                    console = connect_console(1)
                    try:
                        token = ('round-%d' % iteration).encode()
                        command = b'ping:' + token + b'\n'
                        assert os.write(console, command) == len(command)
                        received = bytearray()
                        deadline = time.monotonic() + 5
                        pattern = rb'MK_CHILD_PONG token=' + token + rb'\r?\n'
                        while not re.search(pattern, received):
                            assert time.monotonic() < deadline, 'stress roundtrip timed out'
                            drain_console(console, received, 0.1)
                        # Deliberately release with another response potentially
                        # in flight. The next iteration does not rely on it.
                        closing = ('ping:close-%d\n' % iteration).encode()
                        assert os.write(console, closing) == len(closing)
                    finally:
                        os.close(console)
                counts[index] += 1
                barrier.wait()
        except Exception as error:
            errors.append(repr(error))
            barrier.abort()
        finally:
            windows[index] = [start, time.monotonic_ns()]

    threads = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(2)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 180
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    assert not any(thread.is_alive() for thread in threads), 'native worker did not drain'
    assert not errors, errors
    assert counts == [64, 64], counts
    assert max(window[0] for window in windows) < min(window[1] for window in windows)
    return dict(unload_rejections=counts[0], console_roundtrips=counts[1],
                console_closes=counts[1], closing_sends=counts[1], worker_windows=windows,
                incoming_workers_exercised=False)


def register_probe(trace_dir, command):
    fd = None
    try:
        # Buffered append seeks to EOF; tracefs seq files reject SEEK_END.
        # Do not truncate: already enabled probes must remain registered.
        fd = os.open(trace_dir / 'kprobe_events', os.O_WRONLY | os.O_APPEND)
        data = (command + '\n').encode()
        assert os.write(fd, data) == len(data), 'short probe registration'
    except OSError as error:
        raise RuntimeError('probe registration failed: ' + command) from error
    finally:
        if fd is not None:
            os.close(fd)


def require_failed_overlay(base, data):
    overlays = base / 'overlays'
    before = set(overlays.glob('tx_*'))
    assert (overlays / 'new').write_bytes(data) == len(data)
    created = set(overlays.glob('tx_*')) - before
    assert len(created) == 1, 'missing or ambiguous removal transaction'
    transaction = created.pop()
    assert transaction.name.removeprefix('tx_').isdigit()
    assert (transaction / 'status').read_text().strip() == 'failed'
    assert (transaction / 'instance').read_text().strip() == '/instances'
    assert (transaction / 'dtbo').read_bytes() == data
    return transaction.name


def mutate_image(data, case):
    assert len(data) >= 64
    changed = bytearray(data)
    if case == 'bad-magic':
        changed[56] ^= 1
    elif case == 'bad-text-offset':
        changed[8:16] = (4096).to_bytes(8, 'little')
    elif case == 'image-too-large':
        changed[16:24] = (512 * 1024 * 1024).to_bytes(8, 'little')
    else:
        raise ValueError('unsupported header mutation')
    return changed


@contextmanager
def load_fixture(data, size=None):
    # kernel_read_file() denies writable-open files, even if flushed.
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'load-fixture'
        with path.open('wb') as output:
            output.write(data)
            if size is not None:
                output.truncate(size)
        with path.open('rb') as source:
            yield source


def main():
    mount('proc', '/proc', 'proc')
    args = Path('/proc/cmdline').read_text().split()
    assert 'mk_lifecycle_guard=modern-v5' in args
    options = dict(arg.split('=', 1) for arg in args if arg.startswith('mk_lifecycle_') and '=' in arg)
    mode = options.get('mk_lifecycle_mode', 'graceful')
    harts = int(options.get('mk_lifecycle_harts', '1'))
    cycles = int(options.get('mk_lifecycle_cycles', '1'))
    images = options.get('mk_lifecycle_images', 'same')
    fault = int(options.get('mk_lifecycle_fault', '0'))
    assert mode in ('graceful', 'halt', 'poweroff', 'reboot', 'panic-retain',
                    'deny-primary', 'partial-start', 'stuck-stop', 'loader-negative',
                    'failed-retain', 'lost-ack', 'writer-stress',
                    'manifest-prepare', 'manifest-capacity', 'placement-negative')
    placement_negative = mode == 'placement-negative'
    manifest_fault = {'manifest-prepare': (1, errno.ENOMEM),
                      'manifest-capacity': (2, errno.ENOSPC)}.get(mode)
    assert harts in (1, 2) and 1 <= cycles <= 50
    assert images in ('same', 'alternate') and (images == 'same' or cycles >= 2)
    if mode in ('deny-primary', 'partial-start', 'stuck-stop'):
        assert harts == 2 and cycles == 1 and images == 'same'
        assert fault in {'deny-primary': (1, 2, 3, 4), 'partial-start': (5,), 'stuck-stop': (7,)}[mode]
    if mode == 'loader-negative':
        assert cycles == 1 and images == 'same' and fault == 0
    if manifest_fault:
        assert cycles == 1 and images == 'same' and fault == 0
        assert 'mk_test_manifest_fault=' + str(manifest_fault[0]) in args
    assert ('mk_test_bad_placement=1' in args) == placement_negative
    if placement_negative:
        assert cycles == 1 and images == 'same' and fault == 0
        assert 'mk_test_manifest_fault=0' in args
        assert 'mk_test_resource_trace=1' in args
    if mode in ('failed-retain', 'lost-ack', 'panic-retain'):
        assert harts == 2 and cycles == 1 and images == 'same'
        assert fault in {'failed-retain': (8,), 'lost-ack': (0, 7), 'panic-retain': (0,)}[mode]
    if mode == 'writer-stress':
        assert harts == 2 and cycles == 1 and images == 'same' and fault == 0
    mount('sysfs', '/sys', 'sysfs')
    mount('devtmpfs', '/dev', 'devtmpfs')
    # Preserve all host printk records, but do not interleave them with JSON.
    # The complete retained host dmesg is emitted for fail-closed verification.
    subprocess.run(['/bin/busybox', 'dmesg', '-n', '1'], check=True)
    mount('none', str(BASE), 'multikernel')
    mount('tracefs', '/sys/kernel/tracing', 'tracefs')
    trace_dir = Path('/sys/kernel/tracing')
    (trace_dir / 'kprobe_events').write_text(
        'r:mk_hsm_status sbi_hsm_hart_get_status hart=$arg1:u64 state=$retval:s32\n')
    (trace_dir / 'events/kprobes/mk_hsm_status/enable').write_text('1\n')
    if mode in ('stuck-stop', 'loader-negative', 'failed-retain', 'lost-ack', 'panic-retain') or manifest_fault or placement_negative:
        for command in ('p:mk_copy kimage_load_segment', 'p:mk_start sbi_hsm_hart_start'):
            register_probe(trace_dir, command)
        for event in ('mk_copy', 'mk_start'):
            (trace_dir / ('events/kprobes/' + event + '/enable')).write_text('1\n')
    trace = trace_dir / 'trace'
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    from kerf.topology import logical_to_apic
    from kerf.exec.main import boot_multikernel
    from kerf.kill.main import halt_multikernel
    from kerf.load.main import kexec_file_load, KEXEC_MULTIKERNEL, KEXEC_MK_ID
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD
    from kerf.runtime import DeviceTreeManager

    def cli(*argv):
        subprocess.run(['/usr/bin/python3', '-B', '-m', 'kerf.cli', *argv], check=True, timeout=60)

    def status():
        return (BASE / 'instances/lifecycle-test/status').read_text().strip()

    ids = [logical_to_apic()[i] for i in range(1, harts + 1)]
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-3'
    host_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    marker('BEGIN', mode=mode, harts=ids, cycles=cycles, host_boot=host_boot, images=images, fault=fault)
    cli('init', '--cpus=' + ','.join(map(str, ids)), '--memory=512MB', '--devices=none')
    cli('create', 'lifecycle-test', '--id=1', '--cpus=' + ','.join(map(str, ids)), '--memory=256MB')
    if mode in ('failed-retain', 'lost-ack', 'panic-retain'):
        sys.path.insert(0, '/payload')
        from verify_retention import (resources, release_control, loaded_extents,
                                      retention_window, hsm_samples, retention_trace)

        def dmesg():
            return subprocess.check_output(['/bin/busybox', 'dmesg']).decode()

        def snapshot(state, require_ctrl=True):
            rows = resources(dmesg(), state, require_ctrl=require_ctrl)
            assert rows, 'no published allocation snapshot: ' + state
            return rows[-1]

        # Positive release control before any hart is started or fault armed.
        with open('/payload/vmlinux', 'rb') as kernel, open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
            kexec_file_load(kernel.fileno(), initrd.fileno(),
                            'rdinit=/init console=mktty0 panic=1 mk_lifecycle_child=1',
                            KEXEC_MULTIKERNEL | KEXEC_MK_ID(1))
        # The control block is lazy: manifest finalization allocates it at exec.
        control_resources = snapshot('loaded', require_ctrl=False)
        control_extent = loaded_extents(dmesg())[-1]
        control_start = len(dmesg())
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
        assert status() == 'ready'
        cli('delete', 'lifecycle-test')
        deadline = time.monotonic() + 20
        while True:
            control = dict(resources=control_resources, release_log=dmesg()[control_start:],
                           image_extent=control_extent, host_alive=True)
            try:
                release_control(control)
                break
            except ValueError:
                assert time.monotonic() < deadline, 'release control incomplete'
                time.sleep(0.05)
        marker('CONTROL', **control)
        cli('create', 'lifecycle-test', '--id=1', '--cpus=' + ','.join(map(str, ids)), '--memory=256MB')

        def retain(state, before, positive_trace, ownership_before=None):
            nonlocal fd
            assert 'mk_copy:' in positive_trace and 'mk_start:' in positive_trace
            assert (trace_dir / 'tracing_on').read_text().strip() == '1'
            if state == 'active':
                Path('/dev/kmsg').write_text(f'MK_TEST_RETAIN_BEGIN id=1 mode={mode} host_boot={host_boot}\n')
            prefix = dmesg()

            def observed_log():
                log = dmesg()
                assert log.startswith(prefix), 'dmesg retention window was overwritten'
                return log[len(prefix):]

            if state == 'active':
                wait_retained_harts(lambda: boot_multikernel(1), observed_log, ids, 3 if fault == 7 else 1)
                drain_console(fd, received)
                os.close(fd)
                fd = None
            if ownership_before is None:
                ownership_before = {path: (BASE / path).read_bytes() for path in
                                    ('device_tree', 'instances/lifecycle-test/device_tree')}
            root_before = ownership_before['device_tree']
            instance_before = ownership_before['instances/lifecycle-test/device_tree']
            removal = DeviceTreeManager().overlay_gen.generate_removal_overlay('lifecycle-test')
            checks = {}
            destroy_tx = None
            for name, operation in {
                'exec': lambda: boot_multikernel(1),
                'unload': lambda: kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD),
                'destroy': lambda: require_failed_overlay(BASE, removal),
            }.items():
                if state != 'active':
                    trace.write_text('\n')
                if name == 'destroy':
                    destroy_tx = operation()
                    result = 'failed'
                else:
                    result = require_errno(operation, errno.EBUSY)
                # Reading trace pauses recording. ACTIVE lanes capture once,
                # after all operations and the deferred-release observation.
                evidence = '' if state == 'active' else trace.read_text()
                assert 'mk_copy:' not in evidence and 'mk_start:' not in evidence
                checks[name] = dict(error=result, trace=evidence.splitlines())
                assert status() == state
                assert (BASE / 'device_tree').read_bytes() == root_before
                assert (BASE / 'instances/lifecycle-test/device_tree').read_bytes() == instance_before
            after = resources(observed_log(), state, strict=True)[-1]
            for key in ('image', 'ctrl', 'manifest', 'ring', 'pool', 'size', 'owned', 'ring_size', 'manifest_size'):
                assert before[key] == after[key], (key, before, after)
            assert after['tracked'] == 2
            # Do not rely on a console-held instance reference for retention.
            # Give any deferred release worker a scheduling opportunity.
            time.sleep(0.2)
            log = observed_log()
            assert 'MK_TEST_FREE id=1 ' not in log
            assert re.search(r'Failed to apply overlay transaction ' + destroy_tx[3:] + r': -16\b', log)
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
            extra = {}
            if state == 'active':
                (trace_dir / 'trace_marker').write_text(
                    f'MK_RETENTION_GUARD_END id=1 mode={mode} host_boot={host_boot}\n')
                guard_trace = trace.read_text()
                health = dict(enabled={'tracing_on': (trace_dir / 'tracing_on').read_text().strip(),
                                       **{name: (trace_dir / f'events/kprobes/{name}/enable').read_text().strip()
                                          for name in ('mk_copy', 'mk_start')}},
                              stats={path.parent.name: path.read_text()
                                     for path in (trace_dir / 'per_cpu').glob('cpu*/stats')})
                retention_trace(guard_trace, health, mode, host_boot)
                for row in checks.values():
                    row['trace'] = guard_trace.splitlines()
                Path('/dev/kmsg').write_text(f'MK_TEST_RETAIN_END id=1 mode={mode} host_boot={host_boot}\n')
                log = retention_window(dmesg(), mode, host_boot)
                groups = hsm_samples(log, ids)
                assert len(groups) >= 2 and all(value == (3 if fault == 7 else 1)
                                               for value in groups[-1]['states'].values())
                extra = dict(host_boot=host_boot, guard_trace=guard_trace.splitlines(), trace_health=health,
                             observed_state='stop-pending' if fault == 7 else 'stopped')
                print('MK_RETENTION_TRACE_BEGIN guarded\n' + guard_trace.rstrip() +
                      '\nMK_RETENTION_TRACE_END guarded', flush=True)
            marker('RETAINED', state=state, harts=ids, checks=checks, resources_before=before,
                   resources_after=after, guard_log=log, positive_trace=positive_trace.splitlines(),
                   no_copy_or_start=True, ownership_unchanged=True, tracer_exercised=True,
                   host_alive=True, destroy_tx=destroy_tx, **extra)
            marker('PASS', mode=mode, cycles=1, host_alive=True, host_boot=host_boot,
                   retained_until_vm_shutdown=True)
            subprocess.run(['/bin/busybox', 'dmesg'], check=True)
    seen_boots = set()
    image_start = None
    if manifest_fault or placement_negative:
        sys.path.insert(0, '/payload')
        from verify_retention import resources, release_control, loaded_extents
    for cycle in range(1, cycles + 1):
        payload = Path('/payload/vmlinux-alt' if images == 'alternate' and cycle % 2 == 0
                       else '/payload/vmlinux')
        expected_release = Path(str(payload) + '.release').read_text().strip()
        image_sha = hashlib.sha256(payload.read_bytes()).hexdigest()
        if mode == 'loader-negative':
            assert status() == 'ready'
            ownership = {path: (BASE / path).read_bytes() for path in
                         ('device_tree', 'instances/lifecycle-test/device_tree')}
            for case, expected in (('bad-magic', errno.EINVAL), ('bad-text-offset', errno.EINVAL),
                                   ('image-too-large', errno.ENOMEM), ('initrd-too-large', errno.ENOMEM)):
                trace.write_text('\n')
                kernel_data = payload.read_bytes()
                initrd_data = Path('/payload/secondary-initrd.cpio.gz').read_bytes()
                initrd_size = None
                if case == 'initrd-too-large':
                    # Exceeds the 256MiB grant after Image allocation;
                    # tests partial-loader allocation rollback, not only probe rejection.
                    initrd_data = b''
                    initrd_size = 256 * 1024 * 1024
                else:
                    kernel_data = mutate_image(kernel_data, case)
                with load_fixture(kernel_data) as bad_kernel, \
                        load_fixture(initrd_data, size=initrd_size) as bad_initrd:
                    result = require_errno(lambda: kexec_file_load(
                        bad_kernel.fileno(), bad_initrd.fileno(),
                        'rdinit=/init console=mktty0 panic=1 mk_lifecycle_child=1',
                        KEXEC_MULTIKERNEL | KEXEC_MK_ID(1)), expected)
                evidence = trace.read_text()
                assert 'mk_copy:' not in evidence and 'mk_start:' not in evidence
                assert status() == 'ready'
                assert all((BASE / path).read_bytes() == data for path, data in ownership.items())
                marker('LOAD_REJECTED', case=case, error=result, state='ready',
                       no_copy_or_start=True, ownership_unchanged=True)
        if placement_negative:
            assert status() == 'ready'
            ownership = {path: (BASE / path).read_bytes() for path in
                         ('device_tree', 'instances/lifecycle-test/device_tree')}
            log_start = len(subprocess.check_output(['/bin/busybox', 'dmesg']))
            trace.write_text('\n')
            # Valid Image/initrd: only the native physical-placement hook faults.
            with payload.open('rb') as kernel, open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
                result = require_errno(lambda: kexec_file_load(
                    kernel.fileno(), initrd.fileno(),
                    'rdinit=/init console=mktty0 panic=1 mk_lifecycle_child=1',
                    KEXEC_MULTIKERNEL | KEXEC_MK_ID(1)), errno.ENOMEM)
            evidence = trace.read_text()
            guard_log = subprocess.check_output(['/bin/busybox', 'dmesg'])[log_start:].decode()
            assert 'mk_copy:' not in evidence and 'mk_start:' not in evidence
            assert (trace_dir / 'tracing_on').read_text().strip() == '1'
            assert status() == 'ready'
            assert all((BASE / path).read_bytes() == data for path, data in ownership.items())
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            print('MK_PLACEMENT_TRACE_BEGIN rejected\n' + '\n'.join(evidence.splitlines()) +
                  '\nMK_PLACEMENT_TRACE_END rejected', flush=True)
            marker('PLACEMENT_REJECTED', error=result, state='ready',
                   ownership_unchanged=True, host_boot=host_boot,
                   trace=evidence.splitlines(), guard_log=guard_log)
            # One-shot fault consumed: retry the same unmodified payload.
            trace.write_text('\n')
        with payload.open('rb') as kernel, open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
            kexec_file_load(kernel.fileno(), initrd.fileno(),
                            'rdinit=/init console=mktty0 panic=1 mk_lifecycle_child=1',
                            KEXEC_MULTIKERNEL | KEXEC_MK_ID(1))
        placements = re.findall(rb'kexec_file\(Image\): Loaded kernel at (0x[0-9a-f]+)',
                                subprocess.check_output(['/bin/busybox', 'dmesg']))
        assert placements, 'no loader placement evidence'
        placement = int(placements[-1], 16)
        assert image_start is None or image_start == placement
        image_start = placement
        assert status() == 'loaded'
        if manifest_fault:
            ownership = {path: (BASE / path).read_bytes() for path in
                         ('device_tree', 'instances/lifecycle-test/device_tree')}
            log_start = len(subprocess.check_output(['/bin/busybox', 'dmesg']))
            trace.write_text('\n')
            result = require_errno(lambda: boot_multikernel(1), manifest_fault[1])
            evidence = trace.read_text()
            guard_log = subprocess.check_output(['/bin/busybox', 'dmesg'])[log_start:].decode()
            assert 'mk_copy:' in evidence and 'mk_start:' not in evidence
            assert 'MK_TEST_FREE id=1 ' not in guard_log
            assert (trace_dir / 'tracing_on').read_text().strip() == '1'
            assert status() == 'loaded'
            assert all((BASE / path).read_bytes() == data for path, data in ownership.items())
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            for hart in ids:
                assert re.search(r'hart=' + str(hart) + r' state=1\b', evidence)
            marker('MANIFEST_REJECTED', error=result, state='loaded',
                   ownership_unchanged=True, host_boot=host_boot,
                   trace=evidence.splitlines(), guard_log=guard_log)
            # One-shot fault is consumed: retry the same loaded Image, not a reload.
            trace.write_text('\n')
        fd = connect_console(1)
        received = bytearray()

        def read_until(pattern):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                found = re.search(pattern, received)
                if found:
                    return found
                drain_console(fd, received, 1)
            raise AssertionError('child marker timed out')

        try:
            if mode in ('failed-retain', 'lost-ack', 'panic-retain'):
                trace.write_text('\n')
            if mode == 'failed-retain':
                result = require_errno(lambda: boot_multikernel(1), errno.EPERM)
                assert status() == 'failed'
                positive_trace = trace.read_text()
                assert 'mk_copy:' in positive_trace and 'mk_start:' in positive_trace
                marker('REJECTED', error=result, state='failed', tracer_exercised=True)
                os.close(fd)
                fd = None
                retain('failed', snapshot('failed'), positive_trace)
                return
            if mode == 'deny-primary':
                trace.write_text('\n')
                result = require_errno(lambda: boot_multikernel(1), errno.EINVAL if fault == 2 else errno.EPERM)
                assert status() == 'failed'
                assert (BASE / 'instances/lifecycle-test/id').read_text().strip() == '1'
                kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
                assert status() == 'ready'
                evidence = trace.read_text()
                for hart in ids:
                    assert re.search(r'hart=' + str(hart) + r' state=1\b', evidence)
                assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
                assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
                marker('REJECTED', error=result, harts=ids, host_alive=True, cleanup='ready',
                       hsm_trace=[line for line in evidence.splitlines() if 'mk_hsm_status:' in line])
                continue
            if placement_negative:
                (trace_dir / 'trace_marker').write_text('MK_PLACEMENT_EXEC\n')
            boot_multikernel(1)
            ready = read_until(rb'MK_CHILD_READY online=(\S+) present=(\S+) possible=(\S+) boot=(\S+) release=(\S+)\r?\n')
            mappings = {int(a): int(b, 16) for a, b in re.findall(rb'MK_CHILD_CPU logical=(\d+) reg=([0-9a-f]+)', received)}
            online = cpu_set(ready[1].decode())
            present = cpu_set(ready[2].decode())
            assert {mappings[cpu] for cpu in present} == set(ids)
            if mode == 'partial-start':
                assert len(online) == 1 and online < present
            else:
                assert online == present
            assert len(cpu_set(ready[3].decode())) == 4
            assert ready[4] not in seen_boots
            assert ready[5].decode() == expected_release
            seen_boots.add(ready[4])
            os.write(fd, b'ping\n')
            read_until(rb'MK_CHILD_PONG\r?\n')
            if mode in ('stuck-stop', 'loader-negative', 'lost-ack', 'panic-retain'):
                # Positive controls precede active-unload polling and trace clear.
                before = trace.read_text()
                assert 'mk_copy:' in before and 'mk_start:' in before
                assert (trace_dir / 'tracing_on').read_text().strip() == '1'
            ownership = (BASE / 'instances/lifecycle-test/device_tree').read_bytes()
            require_errno(lambda: kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD), errno.EBUSY)
            assert status() == 'active'
            assert (BASE / 'instances/lifecycle-test/device_tree').read_bytes() == ownership
            marker('CHILD', cycle=cycle, boot=ready[4].decode(), assigned=ids,
                   online=sorted(online), ring_roundtrip=True, release=ready[5].decode(),
                   image_sha=image_sha, image_start=placement, active_unload_rejected=True)
            if mode == 'loader-negative':
                marker('LOADER_RECOVERED', tracer_exercised=True)
            if manifest_fault:
                evidence = trace.read_text()
                assert 'mk_copy:' in evidence and 'mk_start:' in evidence
                marker('MANIFEST_RECOVERED', trace=evidence.splitlines())
            if placement_negative:
                evidence = trace.read_text()
                assert 'mk_copy:' in evidence and 'mk_start:' in evidence
                assert (trace_dir / 'tracing_on').read_text().strip() == '1'
                print('MK_PLACEMENT_TRACE_BEGIN recovered\n' + '\n'.join(evidence.splitlines()) +
                      '\nMK_PLACEMENT_TRACE_END recovered', flush=True)
                marker('PLACEMENT_RECOVERED', trace=evidence.splitlines())
            if mode == 'writer-stress':
                force_error = require_errno(lambda: halt_multikernel(1, force=True), errno.EOPNOTSUPP)
                assert status() == 'active'
                assert (BASE / 'instances/lifecycle-test/device_tree').read_bytes() == ownership
                # The original connection would receive replies before new
                # connections, masking the release/receive exercise.
                os.close(fd)
                fd = None
                result = writer_stress(lambda: kexec_file_unload(
                    KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD))
                result['force_stop_error'] = force_error
                assert status() == 'active'
                assert (BASE / 'instances/lifecycle-test/device_tree').read_bytes() == ownership
                marker('STRESS', cycle=cycle, **result)
                fd = connect_console(1)
            if mode in ('lost-ack', 'panic-retain'):
                positive_trace = trace.read_text()
                # ACTIVE publication precedes architecture start/tracking.
                # Use this only for allocation identity; the anchored post-
                # shutdown window must contain fresh tracked=2 snapshots.
                before = snapshot('active')
                ownership_before = {path: (BASE / path).read_bytes() for path in
                                    ('device_tree', 'instances/lifecycle-test/device_tree')}
                print('MK_RETENTION_TRACE_BEGIN positive\n' + positive_trace.rstrip() +
                      '\nMK_RETENTION_TRACE_END positive', flush=True)
                trace.write_text('\n')
                (trace_dir / 'trace_marker').write_text(
                    f'MK_RETENTION_GUARD_BEGIN id=1 mode={mode} host_boot={host_boot}\n')
            if mode == 'panic-retain':
                os.write(fd, b'panic\n')
                read_until(rb'MK_CHILD_ACTION mode=panic\r?\n')
                read_until(rb'Rebooting in 1 seconds[^\n]*\n')
                assert status() == 'active'
                marker('PANIC', state='active', host_boot=host_boot, timeout=1)
                retain('active', before, positive_trace, ownership_before)
                return
            if mode == 'lost-ack':
                started = time.monotonic()
                result = require_errno(lambda: halt_multikernel(1), errno.ETIMEDOUT)
                elapsed = time.monotonic() - started
                assert 29 <= elapsed <= 65 and status() == 'active'
                drops = re.findall(r'MK_TEST_ACK_DROPPED type=(\d+) operation=(\d+) resource=(\d+) request=(\d+) result=(-?\d+)', dmesg())
                assert len(drops) == 1
                ack = dict(zip(('type','operation','resource','request','result'), map(int, drops[0])))
                assert ack['type'] == 0x3000 and ack['operation'] == 0x3002
                assert ack['resource'] == 1 and ack['request'] > 0 and ack['result'] == 0
                marker('TIMEOUT', error=result, state='active', elapsed=elapsed, ack=ack)
                retain('active', before, positive_trace, ownership_before)
                return
            trace.write_text('\n')
            if mode in ('graceful', 'partial-start', 'stuck-stop', 'loader-negative', 'writer-stress') or manifest_fault or placement_negative:
                if mode == 'stuck-stop':
                    require_errno(lambda: halt_multikernel(1), errno.EBUSY)
                    assert status() == 'active'
                    root_before = (BASE / 'device_tree').read_bytes()
                    instance_before = (BASE / 'instances/lifecycle-test/device_tree').read_bytes()
                    removal = DeviceTreeManager().overlay_gen.generate_removal_overlay('lifecycle-test')
                    results = {}
                    destroy_tx = None
                    operations = {
                        'exec': lambda: boot_multikernel(1),
                        'unload': lambda: kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD),
                        'destroy': lambda: require_failed_overlay(BASE, removal),
                    }
                    for name, operation in operations.items():
                        trace.write_text('\n')
                        if name == 'destroy':
                            destroy_tx = operation()
                            results[name] = 'failed'
                        else:
                            results[name] = require_errno(operation, errno.EBUSY)
                        evidence = trace.read_text()
                        assert 'mk_copy:' not in evidence and 'mk_start:' not in evidence
                        assert status() == 'active'
                        assert (BASE / 'device_tree').read_bytes() == root_before
                        assert (BASE / 'instances/lifecycle-test/device_tree').read_bytes() == instance_before
                    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
                    assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
                    # The overlay API publishes failure in transaction metadata,
                    # not the successful write's errno. Corroborate exact cause.
                    log = subprocess.check_output(['/bin/busybox', 'dmesg']).decode()
                    assert re.search(r'Failed to apply overlay transaction ' +
                                     destroy_tx.removeprefix('tx_') + r': -16\b', log)
                    marker('RETAINED', rejected=results, harts=ids, host_alive=True,
                           state='active', no_copy_or_start=True, ownership_unchanged=True,
                           tracer_exercised=True, destroy_tx=destroy_tx)
                    marker('PASS', mode=mode, cycles=1, host_alive=True, retained_until_vm_shutdown=True)
                    subprocess.run(['/bin/busybox', 'dmesg'], check=True)
                    return
                halt_multikernel(1)
            else:
                os.write(fd, (mode + '\n').encode())
                read_until(rb'MK_CHILD_ACTION mode=' + mode.encode() + rb'\r?\n')
            deadline = time.monotonic() + 20
            while status() != 'loaded':
                assert time.monotonic() < deadline, 'halt did not settle'
                drain_console(fd, received, 0.1)
            drain_console(fd, received)
            evidence = trace.read_text()
            for hart in ids:
                states = re.findall(r'mk_hsm_status:.*\bhart=' + str(hart) + r' state=(-?\d+)\b', evidence)
                assert states and states[-1] == '1', ('latest state is not STOPPED', hart, states)
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
            marker('STOPPED', cycle=cycle, harts=ids, host_alive=True,
                   hsm_trace=[line for line in evidence.splitlines() if 'mk_hsm_status:' in line])
        finally:
            if fd is not None:
                os.close(fd)
        if manifest_fault or placement_negative:
            log = subprocess.check_output(['/bin/busybox', 'dmesg'])
            snapshots = resources(log.decode(), 'loaded')
            assert snapshots, 'missing live resource identity before cleanup'
            release_before = snapshots[-1]
            release_extent = loaded_extents(log.decode())[-1]
            release_start = len(log)
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
        assert status() == 'ready'
    cli('delete', 'lifecycle-test')
    cli('init', '--cpus=none', '--memory=none', '--devices=none')
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-3'
    assert not list((BASE / 'instances').iterdir())
    if manifest_fault or placement_negative:
        deadline = time.monotonic() + 20
        while True:
            log = subprocess.check_output(['/bin/busybox', 'dmesg'])[release_start:].decode()
            released = dict(resources=release_before, release_log=log, image_extent=release_extent)
            try:
                release_control(released)
                break
            except ValueError:
                assert time.monotonic() < deadline, 'resource release incomplete'
                time.sleep(0.05)
        marker('PLACEMENT_RELEASED' if placement_negative else 'MANIFEST_RELEASED', **released)
    marker('PASS', mode=mode, cycles=cycles, host_alive=True)
    subprocess.run(['/bin/busybox', 'dmesg'], check=True)


if __name__ == '__main__':
    if os.getpid() != 1 or platform.machine() != 'riscv64':
        raise SystemExit('refusing operations outside RISC-V guest PID1')
    try:
        main()
    except Exception as error:
        marker('FAIL', error=repr(error))
        traceback.print_exc()
        trace = Path('/sys/kernel/tracing/trace')
        if trace.exists():
            print(trace.read_text(), flush=True)
        subprocess.run(['/bin/busybox', 'dmesg'])
    os.sync()
    ctypes.CDLL(None).reboot(0x4321FEDC)
    while True:
        time.sleep(1)
