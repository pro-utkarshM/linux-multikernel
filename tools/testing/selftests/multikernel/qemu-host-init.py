#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded extension of the pinned #35/Kerf guest, not a standalone harness."""
import ctypes
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

BASE = Path('/sys/fs/multikernel')


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


def main():
    mount('proc', '/proc', 'proc')
    args = Path('/proc/cmdline').read_text().split()
    assert 'mk_lifecycle_guard=modern-v5' in args
    options = dict(arg.split('=', 1) for arg in args if arg.startswith('mk_lifecycle_') and '=' in arg)
    mode = options.get('mk_lifecycle_mode', 'graceful')
    harts = int(options.get('mk_lifecycle_harts', '1'))
    cycles = int(options.get('mk_lifecycle_cycles', '1'))
    images = options.get('mk_lifecycle_images', 'same')
    assert mode in ('graceful', 'halt', 'poweroff', 'reboot', 'panic')
    assert harts in (1, 2) and 1 <= cycles <= 50
    assert images in ('same', 'alternate') and (images == 'same' or cycles >= 2)
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
    trace = trace_dir / 'trace'
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    from kerf.topology import logical_to_apic
    from kerf.exec.main import boot_multikernel
    from kerf.kill.main import halt_multikernel
    from kerf.load.main import kexec_file_load, KEXEC_MULTIKERNEL, KEXEC_MK_ID
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD

    def cli(*argv):
        subprocess.run(['/usr/bin/python3', '-B', '-m', 'kerf.cli', *argv], check=True, timeout=60)

    def status():
        return (BASE / 'instances/lifecycle-test/status').read_text().strip()

    ids = [logical_to_apic()[i] for i in range(1, harts + 1)]
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-3'
    host_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    marker('BEGIN', mode=mode, harts=ids, cycles=cycles, host_boot=host_boot, images=images)
    cli('init', '--cpus=' + ','.join(map(str, ids)), '--memory=512MB', '--devices=none')
    cli('create', 'lifecycle-test', '--id=1', '--cpus=' + ','.join(map(str, ids)), '--memory=256MB')
    seen_boots = set()
    image_start = None
    for cycle in range(1, cycles + 1):
        payload = Path('/payload/vmlinux-alt' if images == 'alternate' and cycle % 2 == 0
                       else '/payload/vmlinux')
        expected_release = Path(str(payload) + '.release').read_text().strip()
        image_sha = hashlib.sha256(payload.read_bytes()).hexdigest()
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
            boot_multikernel(1)
            ready = read_until(rb'MK_CHILD_READY online=(\S+) present=(\S+) possible=(\S+) boot=(\S+) release=(\S+)\r?\n')
            mappings = {int(a): int(b, 16) for a, b in re.findall(rb'MK_CHILD_CPU logical=(\d+) reg=([0-9a-f]+)', received)}
            online = cpu_set(ready[1].decode())
            present = cpu_set(ready[2].decode())
            assert online == present and {mappings[cpu] for cpu in present} == set(ids)
            assert len(cpu_set(ready[3].decode())) == 4
            assert ready[4] not in seen_boots
            assert ready[5].decode() == expected_release
            seen_boots.add(ready[4])
            os.write(fd, b'ping\n')
            read_until(rb'MK_CHILD_PONG\r?\n')
            marker('CHILD', cycle=cycle, boot=ready[4].decode(), assigned=ids,
                   online=sorted(online), ring_roundtrip=True, release=ready[5].decode(),
                   image_sha=image_sha, image_start=placement)
            trace.write_text('\n')
            if mode == 'graceful':
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
                assert re.search(r'hart=' + str(hart) + r' state=1\b', evidence), ('no stopped proof', hart)
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
            marker('STOPPED', cycle=cycle, harts=ids, host_alive=True,
                   hsm_trace=[line for line in evidence.splitlines() if 'mk_hsm_status:' in line])
        finally:
            os.close(fd)
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
        assert status() == 'ready'
    cli('delete', 'lifecycle-test')
    cli('init', '--cpus=none', '--memory=none', '--devices=none')
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-3'
    assert not list((BASE / 'instances').iterdir())
    marker('PASS', mode=mode, cycles=cycles, host_alive=True)
    subprocess.run(['/bin/busybox', 'dmesg'], check=True)


if __name__ == '__main__':
    if os.getpid() != 1 or platform.machine() != 'riscv64':
        raise SystemExit('refusing operations outside RISC-V guest PID1')
    try:
        main()
    except Exception as error:
        marker('FAIL', error=repr(error))
        trace = Path('/sys/kernel/tracing/trace')
        if trace.exists():
            print(trace.read_text(), flush=True)
        subprocess.run(['/bin/busybox', 'dmesg'])
    os.sync()
    ctypes.CDLL(None).reboot(0x4321FEDC)
    while True:
        time.sleep(1)
