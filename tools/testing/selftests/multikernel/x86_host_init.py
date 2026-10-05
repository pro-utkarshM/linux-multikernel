#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Executing-child boot gate extending pinned Nickolaev #35 / Kerf recipe.

Only use as PID 1 in the explicitly guarded disposable QEMU guest.
This slice is not worker/IRQ-lifetime concurrency qualification.
"""
import ctypes
import json
import os
from pathlib import Path
import platform
import secrets
import select
import subprocess
import sys
import time

BASE = Path('/sys/fs/multikernel')
NAME = 'native-child'


def marker(name, **fields):
    print('MK_X86_' + name + ' ' + json.dumps(fields, sort_keys=True), flush=True)


def mount(source, target, kind):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    Path(target).mkdir(parents=True, exist_ok=True)
    if libc.mount(source.encode(), target.encode(), kind.encode(), 0, None):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def cli(*args):
    subprocess.run([sys.executable, '-B', '-m', 'kerf.cli', *args],
                   check=True, timeout=60)


def ownership():
    from kerf.dtc.parser import DeviceTreeParser
    data = (BASE / 'instances' / NAME / 'device_tree').read_bytes()
    return sorted(DeviceTreeParser().parse_instance_dtb_from_bytes(data).resources.cpus)


def status(expected):
    actual = (BASE / 'instances' / NAME / 'status').read_text().strip()
    if actual != expected:
        raise RuntimeError(f'instance status {actual}, expected {expected}')
    return actual


def workload():
    from kerf.topology import logical_to_apic
    options = dict(arg.split('=', 1) for arg in Path('/proc/cmdline').read_text().split()
                   if '=' in arg)
    halt = options.get('mk_x86_halt', 'requested')
    if halt not in ('requested', 'force', 'poweroff', 'reboot'):
        raise ValueError('unsupported x86 halt lane')
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-5'
    ids = logical_to_apic()
    host, child, spare = ([ids[i] for i in group]
                          for group in ((0, 1), (2, 3), (4, 5)))
    assert len(set(host + child + spare)) == 6
    marker('BEGIN', host_cpus=host, child_cpus=child, spare_cpus=spare,
           revision=Path('/payload/source-revision').read_text().strip())
    cli('init', '--cpus=' + ','.join(map(str, child + spare)),
        '--memory=768MB', '--devices=none')
    assert Path('/sys/devices/system/cpu/online').read_text().strip() == '0-1'
    cli('create', NAME, '--id=1', '--cpus=' + ','.join(map(str, child)),
        '--memory=512MB')
    assert ownership() == child
    status('ready')
    cli('load', NAME, '--kernel=/payload/vmlinux',
        '--initrd=/payload/child-initrd.cpio.gz', '--console=mktty0',
        '--cmdline=rdinit=/init panic=0 loglevel=7 mk_test=x86-child')
    status('loaded')
    fd = os.open('/dev/mktty', os.O_RDWR | os.O_NONBLOCK)
    try:
        assert os.write(fd, b'1\n') == 2
        cli('exec', NAME)
        status('active')
        deadline = time.monotonic() + 90
        pending = bytearray()
        alive = reply = False
        nonce = secrets.token_hex(8)
        while time.monotonic() < deadline and not reply:
            if not select.select([fd], [], [], 1)[0]:
                continue
            chunk = os.read(fd, 8192)
            if not chunk:
                raise RuntimeError('mktty closed before child reply')
            pending.extend(chunk)
            while b'\n' in pending:
                line, _, pending = pending.partition(b'\n')
                text = line.decode(errors='replace').rstrip('\r')
                print(text, flush=True)
                if text.startswith('MK_X86_CHILD_ALIVE '):
                    record = json.loads(text.partition(' ')[2])
                    assert record['physical_cpus'] == child
                    assert record['online'] == '0-1' and record['pid'] == 1
                    assert not alive
                    alive = True
                    marker('PING', nonce=nonce)
                    command = f'ping {nonce}\n'.encode()
                    assert os.write(fd, command) == len(command)
                if text.startswith('MK_X86_CHILD_REPLY '):
                    assert alive and json.loads(text.partition(' ')[2])['nonce'] == nonce
                    reply = True
        if not reply:
            raise RuntimeError('real child handshake timed out')
        if halt == 'force':
            cli('kill', NAME, '--force')
        elif halt == 'requested':
            cli('kill', NAME)
        else:
            marker('TERMINATION_REQUEST', mode=halt)
            command = f'terminate {halt}\n'.encode()
            assert os.write(fd, command) == len(command)
            deadline = time.monotonic() + 30
            while (BASE / 'instances' / NAME / 'status').read_text().strip() != 'loaded':
                if time.monotonic() >= deadline:
                    raise RuntimeError('voluntary halt did not settle')
                if select.select([fd], [], [], 0.1)[0]:
                    print(os.read(fd, 8192).decode(errors='replace'), end='', flush=True)
        marker('HALTED', mode=halt, status=status('loaded'), assigned_cpus=ownership())
        cli('unload', NAME)
        marker('UNLOADED', status=status('ready'), assigned_cpus=ownership())
        marker('HOST_SURVIVED',
               online=Path('/sys/devices/system/cpu/online').read_text().strip(),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        marker('PASS', slice='executing-child-boot')
    finally:
        os.close(fd)


def main():
    if os.getpid() != 1 or platform.machine() != 'x86_64':
        raise RuntimeError('refusing operations outside x86 guest PID 1')
    mount('proc', '/proc', 'proc')
    if 'mk_test=x86-host' not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('missing explicit host guest boot guard')
    mount('sysfs', '/sys', 'sysfs')
    mount('devtmpfs', '/dev', 'devtmpfs')
    mount('none', str(BASE), 'multikernel')
    os.environ.update(PYTHONHOME='/usr', PYTHONPATH='/usr/lib/python3/dist-packages',
                      PYTHONDONTWRITEBYTECODE='1', PATH='/bin:/usr/bin')
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    try:
        workload()
    except Exception as error:
        marker('FAIL', error=repr(error))
        subprocess.run(['/bin/busybox', 'dmesg'], timeout=10, check=False)
    finally:
        os.sync()
        ctypes.CDLL(None).reboot(0x4321FEDC)
        while True:
            time.sleep(1)


if __name__ == '__main__':
    main()
