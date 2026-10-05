#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""#35 secondary-init extension: real mktty nonce reply, no test-only kernel API."""
import ctypes
import json
import os
from pathlib import Path
import platform
import sys


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
    mount('devtmpfs', '/dev', 'devtmpfs')
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    from kerf.topology import logical_to_apic
    fd = os.open('/dev/mktty0', os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(fd, target)
    if fd > 2:
        os.close(fd)
    marker('CHILD_ALIVE', pid=os.getpid(), instance=1,
           online=Path('/sys/devices/system/cpu/online').read_text().strip(),
           physical_cpus=sorted(logical_to_apic().values()),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           release=os.uname().release)
    for line in sys.stdin:
        fields = line.strip().split()
        if len(fields) == 2 and fields[0] == 'ping':
            marker('CHILD_REPLY', nonce=fields[1])
        else:
            marker('FAIL', error='unexpected child command')


if __name__ == '__main__':
    main()
