#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Native blocked unregister/cleanup versus same-type registration."""
import os
from pathlib import Path
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import NAME, cli, marker, ownership, status
from x86_nested_host_init import main, TERMINAL_CAPTURE, capture_tail
from x86_admission_host_init import Console
from x86_rcu_host_init import GATE, wait
from x86_lockdep import read_debug_locks, probe_child


def registry(fd, pending, nonce, child, spare):
    options = dict(arg.split('=', 1) for arg in Path('/proc/cmdline').read_text().split() if '=' in arg)
    mode = options.get('mk_registry_mode')
    if mode not in ('replace', 'cleanup'):
        raise RuntimeError('explicit registry mode required')
    console = Console(fd, pending, nonce)
    os.sched_setaffinity(0, {2})
    (GATE / 'registry_arm').write_text(f"{1 if mode == 'replace' else 2} {nonce}")
    console.send('registry')
    held = wait(lambda s: len(s['events']) == 5
                and {e['point'] for e in s['events']} == {1, 12, 2, 3, 11}
                and s['waiter_sleeping'] and s['registrar_sleeping']
                and not s['done'] and not s['registration_done'], 1.5)
    (GATE / 'rcu_release').write_bytes(b'1')
    marker('REGISTRY_HELD', nonce=nonce, mode=mode, state=held)
    console.wait('PROCESS_REPLY', op='registry')
    first = wait(lambda s: s['done'] and s['registration_done'] and s['consumed'] == 1, 8)
    if first['registration_result'] != (0 if mode == 'replace' else -108):
        raise RuntimeError('wrong same-type registration outcome')
    console.command('registry')
    count = 15 if mode == 'replace' else 14
    final = wait(lambda s: s['done'] and s['registration_done'] and s['consumed'] == 2
                 and len(s['events']) == count, 8)
    marker('REGISTRY_COMPLETE', nonce=nonce, mode=mode, state=final)
    console.pending = probe_child(fd, console.pending, nonce)
    if mode == 'replace':
        cli('kill', NAME)
        return console.pending
    # Resource/system handlers are now permanently unregistered. Do not
    # manufacture a normal halt/unload result after terminal cleanup.
    marker('REGISTRY_RETAINED', status=status('active'), assigned_cpus=ownership(),
           reclamation='not-attempted')
    pending = capture_tail(fd, console.pending)
    if pending:
        raise RuntimeError('partial terminal child diagnostic')
    marker('NESTED_HOST_SURVIVED',
           debug_locks=read_debug_locks(),
           online=Path('/sys/devices/system/cpu/online').read_text().strip(),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    marker('NESTED_PASS', slice='native-registry-cleanup')
    return TERMINAL_CAPTURE


if __name__ == '__main__':
    main(registry, profile='registry')
