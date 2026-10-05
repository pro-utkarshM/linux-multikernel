#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""H0 native IRQ callback, H1 real unregister, H2 bounded gate release."""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import NAME, cli, marker
from x86_nested_host_init import main
from x86_admission_host_init import Console

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


def complete(state):
    # The consumption counter may become visible before its observation slot.
    return state['done'] and state['consumed'] == 2 and len(state['events']) == 10


def wait(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = json.loads((GATE / 'rcu_status').read_text())
        if state['timed_out'] or state['overflow']:
            raise RuntimeError('IRQ checkpoint timeout/overflow; qualification aborted')
        if predicate(state):
            return state
        time.sleep(0.001)
    raise RuntimeError('native RCU observation deadline expired')


def rcu(fd, pending, nonce, child, spare):
    console = Console(fd, pending, nonce)
    os.sched_setaffinity(0, {2})
    (GATE / 'rcu_arm').write_text(nonce)
    console.send('rcu')
    # Do not wait for the MKTTY reply: H0 is inside the callback being tested.
    held = wait(lambda state: [e['point'] for e in state['events']] == [1, 2, 3]
                and state['waiter_sleeping'] and not state['done'], 1.5)
    (GATE / 'rcu_release').write_bytes(b'1')
    marker('RCU_HELD', nonce=nonce, state=held)
    console.wait('PROCESS_REPLY', op='rcu')
    wait(lambda state: state['done'] and state['consumed'] == 1, 8)
    console.command('rcu')
    final = wait(complete, 8)
    marker('RCU_COMPLETE', nonce=nonce, state=final)
    cli('kill', NAME)
    return console.pending


if __name__ == '__main__':
    main(rcu, profile='rcu')
