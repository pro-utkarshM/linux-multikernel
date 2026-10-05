#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Eight-CPU prerequisite lane; never qualify worker or IRQ races from it."""
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

sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import BASE, NAME, cli, marker, mount, ownership, require_qemu, status

# Terminal registry tests explicitly retain the child and discard the VM.
TERMINAL_CAPTURE = object()


def capture_tail(fd, pending):
    """Bounded console capture before and after confirmed stop, before unload.

    This is evidence capture, not an IRQ/callback retirement assertion. The
    child can still print after its retirement marker; stop confirmation must
    precede the final drain so those diagnostics cannot be hidden by PASS.
    """
    deadline = time.monotonic() + 1
    captured = 0
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(fd, 8192)
        except BlockingIOError:
            continue
        if not chunk:
            break
        captured += len(chunk)
        pending.extend(chunk)
        while b'\n' in pending:
            line, _, pending = pending.partition(b'\n')
            text = line.decode(errors='replace').rstrip('\r')
            print(text, flush=True)
            if text.startswith('MK_X86_FAIL '):
                raise RuntimeError('nested child reported failure; reclamation prohibited')
        if captured > 1024 * 1024:
            raise RuntimeError('child diagnostic flood; qualification aborted')
    return pending


def workload(after_nested=None, *, profile='nested', after_halt=None, after_unload=None):
    from kerf.topology import logical_to_apic
    if Path('/sys/devices/system/cpu/online').read_text().strip() != '0-7':
        raise RuntimeError('eight online host CPUs required')
    ids = logical_to_apic()
    host, child, spare = (sorted(ids[i] for i in group)
                          for group in ((0, 1, 2), (3, 4, 5), (6, 7)))
    if len(set(host + child + spare)) != 8:
        raise RuntimeError('physical topology aliases')
    marker('NESTED_BEGIN', host_cpus=host, child_cpus=child, spare_cpus=spare,
           revision=Path('/payload/source-revision').read_text().strip())
    cli('init', '--cpus=' + ','.join(map(str, child + spare)),
        '--memory=768MB', '--devices=none')
    if Path('/sys/devices/system/cpu/online').read_text().strip() != '0-2':
        raise RuntimeError('three host CPUs not retained')
    cli('create', NAME, '--id=1', '--cpus=' + ','.join(map(str, child)), '--memory=512MB')
    if ownership() != child:
        raise RuntimeError('initial ownership mismatch')
    cli('load', NAME, '--kernel=/payload/vmlinux', '--initrd=/payload/child-initrd.cpio.gz',
        '--console=mktty0', '--cmdline=rdinit=/init panic=0 loglevel=7 '
        f'mk_test=x86-{profile}-child mk_native_concurrency_test=1')
    status('loaded')
    fd = os.open('/dev/mktty', os.O_RDWR | os.O_NONBLOCK)
    try:
        if os.write(fd, b'1\n') != 2:
            raise RuntimeError('short connection write')
        cli('exec', NAME)
        status('active')
        nonce, pending = secrets.token_hex(8), bytearray()
        alive = reply = retired = False
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and not retired:
            if not select.select([fd], [], [], 1)[0]:
                continue
            chunk = os.read(fd, 8192)
            if not chunk:
                raise RuntimeError('child console disappeared')
            pending.extend(chunk)
            while b'\n' in pending:
                line, _, pending = pending.partition(b'\n')
                text = line.decode(errors='replace').rstrip('\r')
                print(text, flush=True)
                if text.startswith('MK_X86_FAIL '):
                    raise RuntimeError('nested child reported failure; reclamation prohibited')
                if text.startswith('MK_X86_CHILD_ALIVE '):
                    record = json.loads(text.partition(' ')[2])
                    if alive or record['physical_cpus'] != child or record['online'] != '0-2':
                        raise RuntimeError('child identity mismatch')
                    alive = True
                    marker('PING', nonce=nonce)
                    command = f'ping {nonce}\n'.encode()
                    if os.write(fd, command) != len(command):
                        raise RuntimeError('short ping')
                if text.startswith('MK_X86_CHILD_REPLY '):
                    if not alive or reply or json.loads(text.partition(' ')[2])['nonce'] != nonce:
                        raise RuntimeError('uncorrelated child reply')
                    reply = True
                    command = f'nested {nonce} {child[-1]}\n'.encode()
                    if os.write(fd, command) != len(command):
                        raise RuntimeError('short nested command')
                if text.startswith('MK_X86_NESTED_POOL_RETIRED '):
                    record = json.loads(text.partition(' ')[2])
                    if not reply or record['nonce'] != nonce or record['cpu'] != child[-1]:
                        raise RuntimeError('uncorrelated nested completion')
                    retired = True
        if not retired:
            raise RuntimeError('nested roundtrip timed out; reclamation prohibited')
        pending = capture_tail(fd, pending)
        if after_nested:
            # The admission callback performs and confirms its drain/halt.
            pending = after_nested(fd, pending, nonce, child, spare)
            if pending is TERMINAL_CAPTURE:
                return
        else:
            cli('kill', NAME)
        pending = capture_tail(fd, pending)
        if pending:
            print(pending.decode(errors='replace'), flush=True)
            raise RuntimeError('incomplete child diagnostic at confirmed halt; qualification aborted')
        marker('NESTED_HALTED', status=status('loaded'), assigned_cpus=ownership())
        if after_halt:
            pending = after_halt(fd, pending, nonce, child, spare)
        else:
            cli('unload', NAME)
        marker('NESTED_UNLOADED', status=status('ready'), assigned_cpus=ownership())
        if after_unload:
            pending = after_unload(fd, pending, nonce, child, spare)
        marker('NESTED_HOST_SURVIVED',
               online=Path('/sys/devices/system/cpu/online').read_text().strip(),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        qualification = 'native-registry-replace' if profile == 'registry' else 'native-' + profile
        marker('NESTED_PASS', slice=qualification if after_nested else 'nested-pool-prerequisite')
    finally:
        os.close(fd)


def main(after_nested=None, *, profile='nested', after_halt=None, after_unload=None):
    if os.getpid() != 1 or platform.machine() != 'x86_64':
        raise RuntimeError('not x86 guest PID 1')
    mount('proc', '/proc', 'proc')
    options = Path('/proc/cmdline').read_text().split()
    if f'mk_test=x86-{profile}-host' not in options or 'mk_native_concurrency_test=1' not in options:
        raise RuntimeError('missing explicit nested host guards')
    mount('sysfs', '/sys', 'sysfs')
    require_qemu()
    mount('devtmpfs', '/dev', 'devtmpfs')
    mount('none', str(BASE), 'multikernel')
    mount('none', '/sys/kernel/debug', 'debugfs')
    os.environ.update(PYTHONHOME='/usr', PYTHONPATH='/usr/lib/python3/dist-packages',
                      PYTHONDONTWRITEBYTECODE='1', PATH='/bin:/usr/bin')
    try:
        workload(after_nested, profile=profile, after_halt=after_halt, after_unload=after_unload)
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
