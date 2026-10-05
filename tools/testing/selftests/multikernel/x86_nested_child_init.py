#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded nested-pool prerequisite using existing #35/Kerf operations."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import BASE, cli, marker, mount, require_qemu
from x86_lockdep import read_debug_locks, child_final


def snapshot():
    from kerf.topology import logical_to_apic
    state = json.loads(Path('/sys/kernel/debug/mk-native-concurrency-test/local_snapshot').read_text())
    if state.pop('instance') != 1:
        raise RuntimeError('not the expected child instance')
    state['online_cpus'] = sorted(logical_to_apic().values())
    return state


def apply_pool(diff):
    from kerf.dtc.overlay import OverlayGenerator
    blob = bytes(OverlayGenerator().generate_pool_overlay(diff))
    previous = set((BASE / 'overlays').glob('tx_*'))
    with (BASE / 'overlays/new').open('wb', buffering=0) as stream:
        if stream.write(blob) != len(blob):
            raise RuntimeError('short overlay write')
    created = set((BASE / 'overlays').glob('tx_*')) - previous
    if len(created) != 1:
        raise RuntimeError('ambiguous overlay transaction')
    transaction = created.pop()
    return {'transaction': int(transaction.name.removeprefix('tx_')),
            'status': (transaction / 'status').read_text().strip()}


def nested(nonce, cpu):
    from kerf.models import PoolMemoryRegion
    from kerf.pool_diff import PoolDiff
    before = snapshot()
    if len(before['owned_cpus']) != 3 or cpu != before['owned_cpus'][-1]:
        raise RuntimeError('invalid nested CPU selection')
    cli('init', '--cpus=' + str(cpu), '--memory=16MB', '--devices=none')
    state = snapshot()
    marker('NESTED_POOL_READY', nonce=nonce, cpu=cpu, **state)
    result = apply_pool(PoolDiff(cpus_to_host=[cpu]))
    state = snapshot()
    marker('NESTED_CPU_RETURN_RESULT', nonce=nonce, cpu=cpu, **result, **state)
    if result['status'] != 'applied' or state['owned_cpus'] != before['owned_cpus']:
        raise RuntimeError('nested CPU return failed; retain nested park allocations')
    if state['online_cpus'] != before['online_cpus'] or state['pool_cpus']:
        raise RuntimeError('nested CPU return did not restore online ownership')
    marker('NESTED_CPU_RETURNED', nonce=nonce, cpu=cpu, **result, **state)
    chunks = [PoolMemoryRegion(base=base, size=size) for base, size in state['chunks']]
    result = apply_pool(PoolDiff(memory_to_host=chunks))
    state = snapshot()
    if (result['status'] != 'applied' or state['pool_cpus'] or state['chunks']
            or state['slot'] != '0' or state['park'] != '0'):
        raise RuntimeError('nested park storage not retired; parent reclamation prohibited')
    marker('NESTED_POOL_RETIRED', nonce=nonce, cpu=cpu, **result, **state)


def main(extra_handler=None, *, profile='nested'):
    if os.getpid() != 1 or platform.machine() != 'x86_64':
        raise RuntimeError('not x86 guest PID 1')
    mount('proc', '/proc', 'proc')
    options = Path('/proc/cmdline').read_text().split()
    if f'mk_test=x86-{profile}-child' not in options or 'mk_native_concurrency_test=1' not in options:
        raise RuntimeError('missing nested guest boot guards')
    mount('sysfs', '/sys', 'sysfs')
    require_qemu()
    mount('devtmpfs', '/dev', 'devtmpfs')
    mount('none', '/sys/kernel/debug', 'debugfs')
    os.environ.update(PYTHONHOME='/usr', PYTHONPATH='/usr/lib/python3/dist-packages',
                      PYTHONDONTWRITEBYTECODE='1', PATH='/bin:/usr/bin')
    fd = os.open('/dev/mktty0', os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(fd, target)
    if fd > 2:
        os.close(fd)
    state = snapshot()
    marker('CHILD_ALIVE', pid=1, instance=1, physical_cpus=state['online_cpus'],
           debug_locks=read_debug_locks(),
           online=Path('/sys/devices/system/cpu/online').read_text().strip(),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    try:
        for line in sys.stdin:
            fields = line.strip().split(maxsplit=2)
            if len(fields) == 2 and fields[0] == 'ping':
                marker('CHILD_REPLY', nonce=fields[1])
            elif len(fields) == 2 and fields[0] == 'lockdep':
                child_final(marker, fields[1])
            elif len(fields) == 3 and fields[0] == 'nested':
                nested(fields[1], int(fields[2]))
            elif extra_handler and len(fields) == 3 and fields[0] == 'process':
                extra_handler(fields[1], json.loads(fields[2]))
            else:
                raise RuntimeError('unexpected nested command')
    except Exception as error:
        marker('FAIL', error=repr(error), snapshot=snapshot())
        subprocess.run(['/bin/busybox', 'dmesg'], timeout=10, check=False)
        # PID1 remains alive. The parent must not reclaim unqualified storage.
        import time
        while True:
            time.sleep(1)


if __name__ == '__main__':
    main()
