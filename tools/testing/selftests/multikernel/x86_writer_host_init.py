#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Unload a stopped child's actual Image while its native ring writer is held."""
import json
import os
from pathlib import Path
import sys
import threading
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import NAME, cli, marker
from x86_nested_host_init import main
from x86_admission_host_init import Operation

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


def wait(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = json.loads((GATE / 'writer_status').read_text())
        if state['failed']:
            raise RuntimeError('native writer gate failed; qualification aborted')
        if predicate(state):
            return state
        time.sleep(0.001)
    raise RuntimeError('native writer observation deadline expired')


def stop(fd, pending, nonce, child, spare):
    cli('kill', NAME)
    return pending


def unload(fd, pending, nonce, child, spare):
    os.sched_setaffinity(0, {2})
    marker('WRITER_BEGIN', nonce=nonce, taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    start = threading.Event()
    def unloader():
        os.sched_setaffinity(0, {1})
        if not start.wait(5):
            raise RuntimeError('Image unloader was never admitted')
        cli('unload', NAME)  # real Kerf kexec_file_load(KEXEC_FILE_UNLOAD)
    operation = Operation(unloader)
    (GATE / 'writer_arm').write_text(nonce)
    wait(lambda s: len(s['events']) == 1, 1)
    start.set()
    held = wait(lambda s: len(s['events']) == 2 and s['events'][-1]['point'] == 2, 1)
    (GATE / 'writer_release').write_bytes(b'1')
    marker('WRITER_HELD', nonce=nonce, state=held)
    operation.finish(10)
    wait(lambda s: s['sent'] and len(s['events']) == 6, 3)
    (GATE / 'writer_probe').write_bytes(b'1')
    final = wait(lambda s: s['probed'], 1)
    marker('WRITER_COMPLETE', nonce=nonce, state=final,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    return pending


if __name__ == '__main__':
    main(stop, profile='writer', after_halt=unload)
