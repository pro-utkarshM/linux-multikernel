#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify real selected MKTTY RX/last-close ordering and post-close delivery."""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle
from x86_kmsg import MAX_LOG, validate_blob
from x86_lockdep import decode_record

SPAWN_MODES = ('spawn-close', 'spawn-hangup', 'spawn-overflow', 'spawn-offline')


def verify_spawn_records(mode, held, final):
    try:
        number = SPAWN_MODES.index(mode) + 1
        session = number in (1, 2)
        for key in ('cookie', 'work'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('spawn identity mismatch')
        for state, done in ((held, False), (final, True)):
            flags = dict(failed=False, released=done, worker_done=done,
                         drained=done and session, reopened=done and session,
                         drain_waiting=not done and session, rx_irq=True)
            if any(state.get(k) is not v for k, v in flags.items()):
                raise ValueError('spawn hold/drain/activation/context not proven')
            counts = dict(mode=number, input=20000 if number == 3 else 32,
                          copied=16384 if number == 3 else 32,
                          dropped=3616 if number == 3 else 0,
                          peak=16384 if number == 3 else 32, discarded=0,
                          inserted=(16384 if number == 3 else 32) if done else 0,
                          dequeued=(16384 if number == 3 else 32) if done else (32 if session else 0))
            if any(type(state.get(k)) is not int or state[k] != v for k, v in counts.items()):
                raise ValueError('spawn byte accounting or mode mismatch')
        points = [1, 2, 3, 4, 5, 9, 6, 7, 8] if session else [1, 2, 5, 9, 6]
        if number == 2:
            points = [1, 2, 10, 3, 4, 5, 9, 6, 7, 11, 8]
        events = final['events']
        if len(events) != len(points) or held['events'] != events[:5 if number == 2 else 4 if session else 2]:
            raise ValueError('spawn event count/prefix mismatch')
        for i, (event, point) in enumerate(zip(events, points), 1):
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != i or event['point'] != point
                    or event['cpu'] not in (0, 1, 2)
                    or event.get('hardirq') is not False or event.get('vector') is not False):
                raise ValueError('spawn worker sequence/context mismatch')
        if number == 4:
            if any(e['cpu'] != 2 for e in events if e['point'] in (1, 2)):
                raise ValueError('worker not executing on selected offline CPU')
            if any(e['cpu'] == 2 for e in events if e['point'] in (9, 6)):
                raise ValueError('worker did not continue away from offline CPU')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify_records(held, final):
    try:
        for key in ('cookie', 'connection', 'buffer'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('MKTTY correlation/identity mismatch')
        if held['connection'] == held['buffer']:
            raise ValueError('connection and RX buffer identities alias')
        for state, closed in ((held, False), (final, True)):
            if (state.get('released') is not closed or state.get('closed') is not closed
                    or state.get('failed') is not False or type(state.get('unmatched')) is not int
                    or state['unmatched'] != int(closed)):
                raise ValueError('unproven hold, reclamation, unmatched RX or clean deadline')
        events = final['events']
        mode = held.get('mode', 'ipi')
        if mode not in ('ipi', 'worker') or final.get('mode', 'ipi') != mode:
            raise ValueError('unknown or mismatched MKTTY mode')
        worker = mode == 'worker'
        points = (1, 4, 10, 6, 11, 12, 3, 13, 14, 7, 8, 9) if worker else tuple(range(1, 10))
        if (worker and (held.get('flush_waiting') is not True or final.get('flush_waiting') is not False)):
            raise ValueError('actual flush completion wait not observed')
        if len(events) != len(points) or held['events'] != events[:6 if worker else 2]:
            raise ValueError('missing or inconsistent MKTTY events')
        for index, event in enumerate(events, 1):
            point = points[index - 1]
            irq = point in (1, 4, 9)
            cpus = (0, 1, 2) if worker and point in (10, 13) else (0,) if irq else (2,) if point == 3 else (1,)
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != index or event['point'] != point
                    or event['cpu'] not in cpus
                    or event.get('hardirq') is not irq or event.get('vector') is not irq):
                raise ValueError('early free, wrong CPU role or non-native RX observation')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify(trace, revision, mode='ipi'):
    errors = verify_nested(trace, revision, qualification='native-tty')
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': expected exactly one event')
            return matches[0].start(), decode_record(matches[0][1])
        begin_at, begin = one('TTY_BEGIN')
        held_at, held = one('TTY_HELD')
        final_at, final = one('TTY_COMPLETE')
        health_at, health = one('TTY_CHILD_HEALTH')
        log_at, log = one('TTY_KMSG_COMPLETE')
        spawn = mode in SPAWN_MODES
        if (mode not in ('ipi', 'worker') + SPAWN_MODES or begin.get('mode', 'ipi') != mode
                or not spawn and held['state'].get('mode', 'ipi') != mode):
            raise ValueError('requested MKTTY mode not exercised')
        nonce = one('PING')[1]['nonce']
        child = one('CHILD_ALIVE')[1]
        confirmed = trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked')
        if not one('NESTED_POOL_RETIRED')[0] < begin_at < held_at < final_at < health_at < confirmed:
            raise ValueError('MKTTY phases out of order')
        if any(v.get('nonce') != nonce for v in (begin, held, final, health)):
            raise ValueError('MKTTY nonce mismatch')
        chunks = list(re.finditer(r'^MK_X86_TTY_KMSG (.*)$', trace, re.M))
        if (log.get('nonce') != nonce or type(log.get('chunks')) is not int
                or not 0 < log['chunks'] == len(chunks) <= 4096
                or not final_at < log_at < health_at):
            raise ValueError('missing or uncorrelated retained child log')
        blob = bytearray()
        for index, match in enumerate(chunks):
            value = json.loads(match[1])
            if (not final_at < match.start() < log_at or value.get('nonce') != nonce
                    or type(value.get('index')) is not int or value['index'] != index
                    or not isinstance(value.get('data'), str) or len(value['data']) > 4096):
                raise ValueError('lost, duplicate, misordered or oversized log chunk')
            blob.extend(base64.b64decode(value['data'], validate=True))
            if len(blob) > MAX_LOG:
                raise ValueError('retained log exceeds bound')
        if (type(log.get('bytes')) is not int or log['bytes'] != len(blob)
                or log.get('sha256') != hashlib.sha256(blob).hexdigest()):
            raise ValueError('retained child log transfer mismatch')
        validate_blob(bytes(blob), nonce, log.get('records'))
        if (any(v.get('taint') != 0 for v in (begin, final, health))
                or health.get('boot_id') != child['boot_id']
                or health.get('online_cpus') != child['physical_cpus']
                or any(v['state']['cookie'] != nonce for v in (held, final))):
            raise ValueError('post-reconnect child health/identity not preserved')
        if spawn:
            errors += verify_spawn_records(mode, held['state'], final['state'])
            if mode in ('spawn-close', 'spawn-hangup'):
                if final.get('fresh') != 'MKTTY_FRESH_' + nonce or final.get('stale') is not False:
                    raise ValueError('fresh session isolation not demonstrated')
            else:
                count = 16384 if mode == 'spawn-overflow' else 32
                if (type(final.get('received')) is not int or final['received'] != count
                        or final.get('sha256') != hashlib.sha256(b'X' * count).hexdigest()):
                    raise ValueError('spawn delivery bytes mismatch')
            if mode == 'spawn-offline':
                if (held.get('offline') != [0, 1] or final.get('offline') != [0, 1]
                        or final.get('restored') != [0, 1, 2]):
                    raise ValueError('CPU offline did not overlap worker continuation')
        else:
            errors += verify_records(held['state'], final['state'])
    except (KeyError, ValueError, TypeError, binascii.Error) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--mode', choices=('ipi', 'worker') + SPAWN_MODES, default='ipi')
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='tty')
    errors += verify(args.trace.read_text(errors='replace'), args.revision, args.mode)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native MKTTY selected RX/final close; ring writer retirement not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
