#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""#35 secondary-init extension: real mktty nonce reply, no test-only kernel API."""
import ctypes
import json
import os
from pathlib import Path
import platform
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_lockdep import read_debug_locks, child_final


def mount(source, target, kind):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    Path(target).mkdir(parents=True, exist_ok=True)
    if libc.mount(source.encode(), target.encode(), kind.encode(), 0, None):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def marker(name, **fields):
    print('MK_X86_' + name + ' ' + json.dumps(fields, sort_keys=True), flush=True)


def main():
    if os.getpid() != 1 or platform.machine() != 'x86_64':
        raise RuntimeError('refusing operations outside x86 guest PID 1')
    mount('proc', '/proc', 'proc')
    if 'mk_test=x86-child' not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('missing child boot guard')
    mount('sysfs', '/sys', 'sysfs')
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or Path('/sys/class/dmi/id/product_name').read_text().strip()
            != 'Standard PC (Q35 + ICH9, 2009)'):
        raise RuntimeError('not the disposable QEMU q35 child lane')
    mount('devtmpfs', '/dev', 'devtmpfs')
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    from kerf.topology import logical_to_apic
    fd = os.open('/dev/mktty0', os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(fd, target)
    if fd > 2:
        os.close(fd)
    lockdep = read_debug_locks
    if 'mk_cpu_reonline_probe=1' in Path('/proc/cmdline').read_text().split():
        # Attribution only: expose baseline debug_locks=0 honestly. The normal
        # frozen verifier still rejects it; never relax acceptance boundaries.
        from x86_reonline import diagnostic_debug_locks
        lockdep = diagnostic_debug_locks
    marker('CHILD_ALIVE', pid=os.getpid(), instance=1,
           debug_locks=lockdep(),
           online=Path('/sys/devices/system/cpu/online').read_text().strip(),
           physical_cpus=sorted(logical_to_apic().values()),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           release=os.uname().release)
    for line in sys.stdin:
        fields = line.strip().split()
        if len(fields) == 2 and fields[0] == 'ping':
            marker('CHILD_REPLY', nonce=fields[1])
        elif len(fields) == 2 and fields[0] == 'lockdep':
            child_final(marker, fields[1])
        elif len(fields) == 2 and fields[0] == 'reonline':
            from x86_reonline import child_probe
            child_probe(fields[1], marker)
        elif len(fields) == 2 and fields[0] == 'terminate' and fields[1] in ('poweroff', 'reboot'):
            os.sync()
            command = 0x4321FEDC if fields[1] == 'poweroff' else 0x01234567
            ctypes.CDLL(None).reboot(command)
            marker('FAIL', error='child termination returned')
        else:
            marker('FAIL', error='unexpected child command')


if __name__ == '__main__':
    main()
