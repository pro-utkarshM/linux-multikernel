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


def command(nonce, fields):
    if fields == {'op': 'burst'}:
        token = ('MKTTY_GATE_' + nonce).encode()
        if os.write(1, token) != len(token):
            raise RuntimeError('short first native TTY write')
        time.sleep(2)
        if os.write(1, token) != len(token):
            raise RuntimeError('short post-close native TTY write')
    elif fields == {'op': 'health'}:
        records = read_records(nonce)
        blob = b''.join(len(record).to_bytes(4, 'big') + record for record in records)
        chunks = [blob[offset:offset + 3072] for offset in range(0, len(blob), 3072)]
        for index, chunk in enumerate(chunks):
            marker('TTY_KMSG', nonce=nonce, index=index,
                   data=base64.b64encode(chunk).decode())
        marker('TTY_KMSG_COMPLETE', nonce=nonce, chunks=len(chunks), bytes=len(blob),
               records=len(records), sha256=hashlib.sha256(blob).hexdigest())
        marker('TTY_CHILD_HEALTH', nonce=nonce,
               taint=int(Path('/proc/sys/kernel/tainted').read_text()),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               online_cpus=snapshot()['online_cpus'])
    else:
        raise RuntimeError('unexpected MKTTY command')


if __name__ == '__main__':
    main(command, profile='tty')
