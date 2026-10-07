#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Send a cookie through the existing user-family ring and real IPI vector."""
from pathlib import Path
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import marker
from x86_nested_child_init import main


def command(nonce, fields):
    if fields != {'op': 'rcu'}:
        raise RuntimeError('unexpected RCU command')
    Path('/sys/kernel/debug/mk-native-concurrency-test/rcu_send').write_text(nonce)
    marker('PROCESS_REPLY', nonce=nonce, op='rcu')


if __name__ == '__main__':
    main(command, profile='rcu')
