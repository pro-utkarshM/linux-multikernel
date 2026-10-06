#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Private one-shot shutdown rejection lanes; no recovery or reclamation."""
import ctypes
import importlib
import os
from pathlib import Path
import select
import termios
import time
from x86_lockdep import decode_record, read_debug_locks

MODES = ('panic-retention', 'contended-poweroff-retention')


def child_terminate(mode):
    from x86_host_init import BASE, mount
    if mode not in MODES:
        raise ValueError('invalid shutdown rejection lane')
    mount('none', '/sys/kernel/debug', 'debugfs')
    if not Path('/sys/kernel/debug/mk-native-concurrency-test/events').exists():
        raise RuntimeError('private observer not enabled')
    if mode == 'contended-poweroff-retention':
        # Reuse the actual controller checkpoint, not a fabricated busy flag.
        from x86_admission_child_init import Admission
        mount('none', str(BASE), 'multikernel')
        gate = Admission()
        gate.handle('shutdown', {'op': 'arm', 'point': 1, 'cpu': 0})
        gate.handle('shutdown', {'op': 'controller'})
        gate.handle('shutdown', {'op': 'held', 'point': 1, 'mode': mode})
        ctypes.CDLL(None).reboot(0x4321FEDC)
    else:
        # Guest-only intentional panic; production panic timeout routes to halt.
        Path('/proc/sysrq-trigger').write_text('c')
    raise RuntimeError('child termination returned')


def host_terminate(fd, pending, nonce, mode, child):
    """Takes ownership of console fd and closes it before any refusal checks."""
    from x86_host_init import marker, capture_tail, ownership, status, rejected, destroy
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD
    from kerf.load.main import KEXEC_MULTIKERNEL, KEXEC_MK_ID
    boot_multikernel = importlib.import_module('kerf.exec.main').boot_multikernel
    fault = Path('/sys/kernel/debug/mk-native-confirm-test')

    def snapshot():
        return dict(allocations=decode_record((fault / 'snapshot').read_text()),
                    owned_cpus=ownership(), fail_cpu=int((fault / 'fail_cpu').read_text()),
                    failures=int((fault / 'failures').read_text()))

    try:
        before = snapshot()
        if (before['fail_cpu'] != 2**64-1 or before['failures'] != 0
                or before['allocations']['state'] != 3 or before['owned_cpus'] != child):
            raise RuntimeError('not an active uninjected instance')
        marker('SHUTDOWN_BEFORE', **before)
        # No console echo: the host emits the observation only after parsing it.
        attributes = termios.tcgetattr(0)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attributes)
        marker('TERMINATION_REQUEST', mode=mode, nonce=nonce)
        command = f'terminate {mode}\n'.encode()
        if os.write(fd, command) != len(command):
            raise RuntimeError('short termination request')
        deadline = time.monotonic() + 45
        data = bytearray()
        while b'\n' not in data:
            if time.monotonic() >= deadline:
                raise RuntimeError('no external terminal observation; no retention claim')
            pending = capture_tail(fd, pending, seconds=0.05)
            if select.select([0], [], [], 0.05)[0]:
                chunk = os.read(0, 512)
                if not chunk:
                    raise RuntimeError('terminal observer channel closed')
                data.extend(chunk)
            if len(data) > 512:
                raise RuntimeError('terminal observer record overflow')
        # The runner relays the actual debugcon record, never a request marker.
        from verify_x86_shutdown import terminal_record
        record = terminal_record(data.decode())
        if record.get('nonce') != nonce or record.get('instance') != 1:
            raise RuntimeError('terminal observation identity mismatch')
        pending = capture_tail(fd, pending)
        if pending:
            raise RuntimeError('incomplete final child console record')
        marker('SHUTDOWN_OBSERVED', **record)
    finally:
        os.close(fd)
    marker('CONSOLE_CLOSED', nonce=nonce)
    status('active')
    exec_errno = rejected(lambda: boot_multikernel(1))
    unload_errno = rejected(lambda: kexec_file_unload(
        KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD))
    destroy_transaction, destroy_status = destroy()
    after = snapshot()
    if after != before:
        raise RuntimeError('retention changed allocations, ownership or fault counters')
    marker('SHUTDOWN_RETAINED', **after, mode=mode, status=status('active'),
           exec_errno=exec_errno, unload_errno=unload_errno,
           destroy_transaction=destroy_transaction, destroy_status=destroy_status)
    marker('HOST_SURVIVED', debug_locks=read_debug_locks(),
           online=Path('/sys/devices/system/cpu/online').read_text().strip(),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    marker('PASS', slice='shutdown-permit-rejection')
