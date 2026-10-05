#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Send two real TTY writes; the second must arrive with no host connection."""
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import marker
from x86_nested_child_init import main, snapshot


def command(nonce, fields):
    if fields == {'op': 'burst'}:
        token = ('MKTTY_GATE_' + nonce).encode()
        if os.write(1, token) != len(token):
            raise RuntimeError('short first native TTY write')
        time.sleep(2)
        if os.write(1, token) != len(token):
            raise RuntimeError('short post-close native TTY write')
    elif fields == {'op': 'health'}:
        marker('TTY_CHILD_HEALTH', nonce=nonce,
               taint=int(Path('/proc/sys/kernel/tainted').read_text()),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               online_cpus=snapshot()['online_cpus'])
    else:
        raise RuntimeError('unexpected MKTTY command')


if __name__ == '__main__':
    main(command, profile='tty')
