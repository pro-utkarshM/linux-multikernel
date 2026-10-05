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

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


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
    os.sched_setaffinity(0, {2})
    marker('TTY_BEGIN', nonce=nonce, taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    start = threading.Event()
    def close():
        os.sched_setaffinity(0, {1})
        if not start.wait(5):
            raise RuntimeError('MKTTY close was never admitted')
        os.close(fd)  # last real file reference; no duplicate/read syscall
    closer = Operation(close)
    (GATE / 'tty_arm').write_text(nonce)
    console.send('burst')
    wait(lambda s: len(s['events']) == 1, 1)
    start.set()
    held = wait(lambda s: len(s['events']) == 2 and s['events'][-1]['point'] == 2, 1)
    (GATE / 'tty_release').write_bytes(b'1')
    marker('TTY_HELD', nonce=nonce, state=held)
    closer.finish(3)
    final = wait(lambda s: s['closed'] and s['unmatched'] == 1 and len(s['events']) == 9, 5)
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
    console.send('health')
    console.wait('TTY_CHILD_HEALTH')
    cli('kill', NAME)
    return console.pending


if __name__ == '__main__':
    main(tty, profile='tty')
