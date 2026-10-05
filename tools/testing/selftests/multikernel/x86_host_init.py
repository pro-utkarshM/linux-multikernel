#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Executing-child boot gate extending pinned Nickolaev #35 / Kerf recipe.

Only use as PID 1 in the explicitly guarded disposable QEMU guest.
This slice is not worker/IRQ-lifetime concurrency qualification.
"""
import ctypes
import errno
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
HALT_MODES = ('requested', 'force', 'poweroff', 'reboot')
HALT_LANES = HALT_MODES + tuple(mode + '-retain' for mode in HALT_MODES)


def require_qemu(identity=Path('/sys/class/dmi/id')):
    try:
        vendor = (identity / 'sys_vendor').read_text().strip()
        product = (identity / 'product_name').read_text().strip()
    except OSError as error:
        raise RuntimeError('missing QEMU q35 identity; refusing resource operations') from error
    if vendor != 'QEMU' or product != 'Standard PC (Q35 + ICH9, 2009)':
        raise RuntimeError('not the disposable QEMU q35 lane; refusing resource operations')


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


def failed_retention(child, console, mode):
    from kerf.kill.main import halt_multikernel
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD
    from kerf.load.main import KEXEC_MULTIKERNEL, KEXEC_MK_ID
    from kerf.dtc.overlay import OverlayGenerator
    fault = Path('/sys/kernel/debug/mk-native-confirm-test')
    if not (fault / 'fail_cpu').exists():
        raise RuntimeError('explicit test-only confirmation interface missing')
    before = json.loads((fault / 'snapshot').read_text())
    owned = ownership()
    assert before['state'] == 3 and owned == child
    failures_before = int((fault / 'failures').read_text())
    (fault / 'fail_cpu').write_text(str(child[-1]) + '\n')

    def rejected(operation):
        try:
            operation()
        except OSError as error:
            assert error.errno == errno.EBUSY, error
            return error.errno
        raise RuntimeError('unsafe operation succeeded after failed confirmation')

    marker('RETENTION_HALT_REQUEST', mode=mode)
    if mode in ('requested', 'force'):
        rejected(lambda: halt_multikernel(1, force=(mode == 'force')))
    else:
        marker('TERMINATION_REQUEST', mode=mode)
        command = f'terminate {mode}\n'.encode()
        assert os.write(console, command) == len(command)
        deadline = time.monotonic() + 30
        # Wait for the actual incoming voluntary-halt worker's failed probe;
        # an unchanged ACTIVE status alone would pass before it ran at all.
        while int((fault / 'failures').read_text()) <= failures_before:
            if time.monotonic() >= deadline:
                raise RuntimeError('voluntary failed-confirmation worker never ran')
            time.sleep(0.05)
    failures_after = int((fault / 'failures').read_text())
    assert failures_after > failures_before
    marker('CONFIRM_FAILURE_OBSERVED', before=failures_before,
           after=failures_after, cpu=child[-1])
    status('active')
    unload_errno = rejected(lambda: kexec_file_unload(
        KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD))

    def destroy():
        # Bypass Kerf's userspace state refusal, not the kernel guard. This is
        # the existing removal overlay, written to the actual kernel entry.
        blob = bytes(OverlayGenerator().generate_removal_overlay(NAME))
        transactions = set((BASE / 'overlays').glob('tx_*'))
        fd = os.open(BASE / 'overlays' / 'new', os.O_WRONLY | os.O_CLOEXEC)
        try:
            assert os.write(fd, blob) == len(blob)
        finally:
            os.close(fd)
        # The ABI accepts a failed transaction too. Identify our directory by
        # the set difference (single writer here), never a latest-tx heuristic.
        created = set((BASE / 'overlays').glob('tx_*')) - transactions
        assert len(created) == 1, created
        transaction = created.pop()
        result = (transaction / 'status').read_text().strip()
        assert result == 'failed', result
        return int(transaction.name.removeprefix('tx_')), result

    destroy_transaction, destroy_status = destroy()
    after = json.loads((fault / 'snapshot').read_text())
    assert before == after and ownership() == owned
    marker('RETAINED', fault_cpu=child[-1], status=status('active'),
           owned_cpus=owned, unload_errno=unload_errno, destroy_status=destroy_status,
           destroy_transaction=destroy_transaction,
           allocations_before=before, allocations_after=after)
    (fault / 'fail_cpu').write_text(str((1 << 64) - 1) + '\n')
    marker('CONFIRM_FAULT_CLEAR', cpu=child[-1])
    halt_multikernel(1, force=True)


def workload():
    from kerf.topology import logical_to_apic
    options = dict(arg.split('=', 1) for arg in Path('/proc/cmdline').read_text().split()
                   if '=' in arg)
    halt = options.get('mk_x86_halt', 'requested')
    if halt not in HALT_LANES:
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
        if halt.endswith('-retain'):
            failed_retention(child, fd, halt.removesuffix('-retain'))
        elif halt == 'force':
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
    require_qemu()
    mount('devtmpfs', '/dev', 'devtmpfs')
    mount('none', str(BASE), 'multikernel')
    if 'mk_native_confirm_test=1' in Path('/proc/cmdline').read_text().split():
        mount('none', '/sys/kernel/debug', 'debugfs')
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
