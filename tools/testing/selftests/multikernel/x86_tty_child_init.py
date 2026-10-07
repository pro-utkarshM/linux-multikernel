#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Send two real TTY writes; the second must arrive with no host connection."""
import os
import base64
import hashlib
from pathlib import Path
import sys
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import marker
from x86_nested_child_init import main, snapshot
from x86_kmsg import read_records

capture = None


def command(nonce, fields):
    global capture
    if set(fields) == {'op', 'mode'} and fields['op'] == 'spawn':
        from x86_spawn_tty import child
        child(nonce, fields['mode'])
    elif fields == {'op': 'burst'}:
        token = ('MKTTY_GATE_' + nonce).encode()
        if os.write(1, token) != len(token):
            raise RuntimeError('short first native TTY write')
        time.sleep(2)
        if os.write(1, token) != len(token):
            raise RuntimeError('short post-close native TTY write')
    elif fields == {'op': 'health'}:
        if capture is not None:
            raise RuntimeError('retained log transfer already active')
        records = read_records(nonce)
        blob = b''.join(len(record).to_bytes(4, 'big') + record for record in records)
        chunks = [blob[offset:offset + 3072] for offset in range(0, len(blob), 3072)]
        capture = dict(nonce=nonce, chunks=chunks, index=0, records=len(records),
                       size=len(blob), digest=hashlib.sha256(blob).hexdigest())
        marker('TTY_KMSG_READY', nonce=nonce, chunks=len(chunks))
    elif (set(fields) == {'op', 'index'} and fields['op'] == 'log-next'):
        if (capture is None or nonce != capture['nonce'] or type(fields['index']) is not int
                or fields['index'] != capture['index']):
            raise RuntimeError('uncorrelated or out-of-order retained log request')
        index = capture['index']
        chunks = capture['chunks']
        marker('TTY_KMSG', nonce=nonce, index=index,
               data=base64.b64encode(chunks[index]).decode())
        capture['index'] += 1
        if capture['index'] != len(chunks):
            return
        marker('TTY_KMSG_COMPLETE', nonce=nonce, chunks=len(chunks), bytes=capture['size'],
               records=capture['records'], sha256=capture['digest'])
        marker('TTY_CHILD_HEALTH', nonce=nonce,
               taint=int(Path('/proc/sys/kernel/tainted').read_text()),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               online_cpus=snapshot()['online_cpus'])
        capture = None
    else:
        raise RuntimeError('unexpected MKTTY command')


if __name__ == '__main__':
    main(command, profile='tty')
