# SPDX-License-Identifier: GPL-2.0
"""Diagnostic sysfs CPU roundtrip, not a pool-return or safe-reclaim test."""
import ctypes
import json
import os
from pathlib import Path
import re
import select
import time


def classify(records, nonce):
    if not re.fullmatch(r'[0-9a-f]{16}', nonce) or len(records) != 3:
        raise ValueError('incomplete re-online evidence')
    for record in records:
        if (not isinstance(record, dict) or record.get('nonce') != nonce
                or type(record.get('cpu')) is not int or record['cpu'] != 1
                or type(record.get('physical_cpu')) is not int
                or record['physical_cpu'] < 0
                or record['physical_cpu'] != records[0]['physical_cpu']):
            raise ValueError('uncorrelated CPU identity')
    before, offline, final = records
    if (before.get('phase') != 'before' or before.get('online') != '0-1'
            or offline.get('phase') != 'offline' or offline.get('online') != '0'):
        raise ValueError('offline transition not demonstrated')
    if (final.get('phase') == 'online' and final.get('online') == '0-1'
            and type(final.get('ran_on')) is int and final['ran_on'] == 1):
        return 'restored'
    if (final.get('phase') == 'error' and final.get('online') == '0'
            and type(final.get('errno')) is int and final['errno'] > 0):
        return 'online-error'
    raise ValueError('unqualified re-online result')


def child_probe(nonce, marker):
    # The ordinary child-init guards ran already; keep the mutating entry
    # explicitly confined even if this module is accidentally reused.
    if (os.getpid() != 1 or not re.fullmatch(r'[0-9a-f]{16}', nonce)
            or 'mk_test=x86-child' not in Path('/proc/cmdline').read_text().split()
            or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'):
        raise RuntimeError('not the explicitly opted-in disposable child')
    from kerf.topology import logical_to_apic
    online = Path('/sys/devices/system/cpu/online')
    control = Path('/sys/devices/system/cpu/cpu1/online')
    ids = logical_to_apic()
    if online.read_text().strip() != '0-1' or set(ids) != {0, 1}:
        raise RuntimeError('two online child CPUs required')
    identity = dict(nonce=nonce, cpu=1, physical_cpu=ids[1])

    def emit(phase, **fields):
        marker('REONLINE', **identity, phase=phase,
               online=online.read_text().strip(), **fields)

    emit('before')
    if control.write_text('0\n') != 2:
        raise RuntimeError('short offline write')
    emit('offline')
    try:
        if control.write_text('1\n') != 2:
            raise RuntimeError('short online write')
    except OSError as error:
        emit('error', errno=error.errno)
        return
    affinity = os.sched_getaffinity(0)
    try:
        os.sched_setaffinity(0, {1})
        emit('online', ran_on=ctypes.CDLL(None).sched_getcpu())
    finally:
        os.sched_setaffinity(0, affinity)


def host_probe(fd, pending, nonce, marker):
    command = f'reonline {nonce}\n'.encode()
    if os.write(fd, command) != len(command):
        raise RuntimeError('short re-online command')
    records = []
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], min(1, max(0, deadline - time.monotonic())))[0]:
            continue
        chunk = os.read(fd, 8192)
        if not chunk:
            raise RuntimeError('child disappeared during re-online')
        pending.extend(chunk)
        while b'\n' in pending:
            line, _, pending = pending.partition(b'\n')
            text = line.decode(errors='replace').rstrip('\r')
            print(text, flush=True)
            if text.startswith('MK_X86_FAIL '):
                raise RuntimeError('child failed during re-online; no reclaim')
            if not text.startswith('MK_X86_REONLINE '):
                continue
            records.append(json.loads(text.partition(' ')[2]))
            if len(records) == 3:
                verdict = classify(records, nonce)
                marker('REONLINE_RESULT', nonce=nonce, verdict=verdict)
                if verdict != 'restored':
                    raise RuntimeError('ordinary CPU re-online failed; no reclaim')
                return pending
    raise RuntimeError('ordinary CPU re-online deadline; no reclaim')
