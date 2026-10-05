#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Close the only host console file during a selected native RX callback."""
import json
import os
from pathlib import Path
import sys
import threading
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import NAME, cli, marker
from x86_nested_host_init import main
from x86_admission_host_init import Console, Operation
from x86_lockdep import probe_child

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


def capture_log(console):
    # MKTTY has bounded RX storage, not transport-level flow control. Pull
    # one chunk only after consuming the previous one; never pace by sleeps.
    console.send('health')
    ready = console.wait('TTY_KMSG_READY')
    chunks = ready.get('chunks')
    if type(chunks) is not int or not 0 < chunks <= 4096:
        raise RuntimeError('invalid retained log transfer size')
    for index in range(chunks):
        console.send('log-next', index=index)
        console.wait('TTY_KMSG', index=index)
    console.wait('TTY_KMSG_COMPLETE', chunks=chunks)
    console.wait('TTY_CHILD_HEALTH')


def wait(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = json.loads((GATE / 'tty_status').read_text())
        if state['failed']:
            raise RuntimeError('native MKTTY gate failed; retain instance resources')
        if predicate(state):
            return state
        time.sleep(0.001)
    raise RuntimeError('native MKTTY observation deadline expired')


def tty(fd, pending, nonce, child, spare):
    console = Console(fd, pending, nonce)
    modes = [word.split('=', 1)[1] for word in Path('/proc/cmdline').read_text().split()
             if word.startswith('mk_tty_mode=')]
    if len(modes) > 1 or modes and modes[0] not in ('ipi', 'worker'):
        raise RuntimeError('invalid native MKTTY mode')
    mode = modes[0] if modes else 'ipi'
    os.sched_setaffinity(0, {2})
    marker('TTY_BEGIN', nonce=nonce, mode=mode,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    start = threading.Event()
    def close():
        os.sched_setaffinity(0, {1})
        if not start.wait(5):
            raise RuntimeError('MKTTY close was never admitted')
        os.close(fd)  # last real file reference; no duplicate/read syscall
    closer = Operation(close)
    (GATE / ('tty_worker_arm' if mode == 'worker' else 'tty_arm')).write_text(nonce)
    console.send('burst')
    wait(lambda s: len(s['events']) == (3 if mode == 'worker' else 1), 1)
    start.set()
    if mode == 'worker':
        held = wait(lambda s: len(s['events']) == 6 and s['events'][-1]['point'] == 12
                    and s['flush_waiting'], 1)
    else:
        held = wait(lambda s: len(s['events']) == 2 and s['events'][-1]['point'] == 2, 1)
    (GATE / 'tty_release').write_bytes(b'1')
    marker('TTY_HELD', nonce=nonce, state=held)
    closer.finish(3)
    final = wait(lambda s: s['closed'] and s['unmatched'] == 1
                 and len(s['events']) == (12 if mode == 'worker' else 9), 5)
    marker('TTY_COMPLETE', nonce=nonce, state=final,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    # Reconnect only AFTER proving delivery without the freed connection.
    new_fd = os.open('/dev/mktty', os.O_RDWR | os.O_NONBLOCK)
    if new_fd != fd:
        os.dup2(new_fd, fd)
        os.close(new_fd)
    if os.write(fd, b'1\n') != 2:
        raise RuntimeError('short reconnect selection')
    console = Console(fd, bytearray(), nonce)
    capture_log(console)
    console.pending = probe_child(fd, console.pending, nonce)
    cli('kill', NAME)
    return console.pending


if __name__ == '__main__':
    main(tty, profile='tty')
