#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded extension of the pinned #35/Kerf guest, not a standalone harness."""
import ctypes
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


def main():
    mount('proc', '/proc', 'proc')
    args = Path('/proc/cmdline').read_text().split()
    assert 'mk_lifecycle_guard=modern-v5' in args
    options = dict(arg.split('=', 1) for arg in args if arg.startswith('mk_lifecycle_') and '=' in arg)
    mode = options.get('mk_lifecycle_mode', 'graceful')
    harts = int(options.get('mk_lifecycle_harts', '1'))
    cycles = int(options.get('mk_lifecycle_cycles', '1'))
    assert mode in ('graceful', 'halt', 'poweroff', 'reboot', 'panic')
    assert harts in (1, 2) and 1 <= cycles <= 50
    mount('sysfs', '/sys', 'sysfs')
    mount('devtmpfs', '/dev', 'devtmpfs')
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
    marker('BEGIN', mode=mode, harts=ids, cycles=cycles, host_boot=host_boot)
    cli('init', '--cpus=' + ','.join(map(str, ids)), '--memory=512MB', '--devices=none')
    cli('create', 'lifecycle-test', '--id=1', '--cpus=' + ','.join(map(str, ids)), '--memory=256MB')
    seen_boots = set()
    for cycle in range(1, cycles + 1):
        with open('/payload/vmlinux', 'rb') as kernel, open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
            kexec_file_load(kernel.fileno(), initrd.fileno(),
                            'rdinit=/init console=mktty0 earlycon=sbi panic=1 mk_lifecycle_child=1',
                            KEXEC_MULTIKERNEL | KEXEC_MK_ID(1))
        assert status() == 'loaded'
        fd = os.open('/dev/mktty', os.O_RDWR | os.O_NONBLOCK)
        received = bytearray()

        def read_until(pattern):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                found = re.search(pattern, received)
                if found:
                    return found
                if not select.select([fd], [], [], 1)[0]:
                    continue
                data = os.read(fd, 4096)
                assert data, 'console closed early'
                print(data.decode(errors='replace'), end='', flush=True)
                received.extend(data)
                assert b'MK_CHILD_FAIL' not in received
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
            seen_boots.add(ready[4])
            os.write(fd, b'ping\n')
            read_until(rb'MK_CHILD_PONG\r?\n')
            marker('CHILD', cycle=cycle, boot=ready[4].decode(), assigned=ids,
                   online=sorted(online), ring_roundtrip=True, release=ready[5].decode())
            trace.write_text('\n')
            if mode == 'graceful':
                halt_multikernel(1)
            else:
                os.write(fd, (mode + '\n').encode())
                read_until(rb'MK_CHILD_ACTION mode=' + mode.encode() + rb'\r?\n')
            deadline = time.monotonic() + 20
            while status() != 'loaded':
                assert time.monotonic() < deadline, 'halt did not settle'
                time.sleep(0.1)
            evidence = trace.read_text()
            for hart in ids:
                assert re.search(r'hart=' + str(hart) + r' state=1\b', evidence), ('no stopped proof', hart)
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host_boot
            assert Path('/proc/sys/kernel/tainted').read_text().strip() == '0'
            marker('STOPPED', cycle=cycle, harts=ids, host_alive=True)
        finally:
            os.close(fd)
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
        assert status() == 'ready'
    cli('delete', 'lifecycle-test')
    cli('init', '--cpus=none', '--memory=none', '--devices=none')
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-3'
    assert not list((BASE / 'instances').iterdir())
    marker('PASS', mode=mode, cycles=cycles, host_alive=True)


if __name__ == '__main__':
    if os.getpid() != 1 or platform.machine() != 'riscv64':
        raise SystemExit('refusing operations outside RISC-V guest PID1')
    try:
        main()
    except Exception as error:
        marker('FAIL', error=repr(error))
        subprocess.run(['/bin/busybox', 'dmesg'])
    os.sync()
    ctypes.CDLL(None).reboot(0x4321FEDC)
    while True:
        time.sleep(1)
