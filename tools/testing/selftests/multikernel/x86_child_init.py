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
    options = dict(arg.split('=', 1) for arg in Path('/proc/cmdline').read_text().split()
                   if '=' in arg)
    if options.get('mk_cpu_reonline_probe') == '1':
        # Isolate hotplug attribution from the baseline's broken MKTTY/IRQ
        # path. QEMU debugcon is a diagnostic sink, not a lifecycle oracle.
        from x86_reonline import child_probe, diagnostic_debug_locks
        port = os.open('/dev/port', os.O_WRONLY)

        def debug_marker(name, **fields):
            line = ('MK_X86_' + name + ' ' + json.dumps(fields, sort_keys=True) + '\n').encode()
            for byte in line:
                if os.pwrite(port, bytes([byte]), 0xe9) != 1:
                    raise RuntimeError('short debugcon write')

        nonce = options['mk_cpu_reonline_nonce']
        debug_marker('PROBE_BOOT', nonce=nonce, debug_locks=diagnostic_debug_locks(),
                     boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     release=os.uname().release)
        try:
            child_probe(nonce, debug_marker)
        except Exception as error:
            debug_marker('PROBE_ERROR', nonce=nonce, error=repr(error))
        finally:
            os.close(port)
        # No normal handshake/teardown claim after this diagnostic operation.
        import time
        while True:
            time.sleep(1)
    fd = os.open('/dev/mktty0', os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(fd, target)
    if fd > 2:
        os.close(fd)
    marker('CHILD_ALIVE', pid=os.getpid(), instance=1,
           debug_locks=read_debug_locks(),
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
        elif len(fields) == 2 and fields[0] == 'terminate' and fields[1].endswith('-retention'):
            from x86_shutdown import child_terminate
            try:
                child_terminate(fields[1])
            except Exception as error:
                marker('FAIL', error=repr(error))
        elif len(fields) == 2 and fields[0] == 'terminate' and fields[1] in ('halt', 'poweroff', 'reboot'):
            os.sync()
            command = {'halt': 0xCDEF0123, 'poweroff': 0x4321FEDC,
                       'reboot': 0x01234567}[fields[1]]
            ctypes.CDLL(None).reboot(command)
            marker('FAIL', error='child termination returned')
        else:
            marker('FAIL', error='unexpected child command')


if __name__ == '__main__':
    main()
