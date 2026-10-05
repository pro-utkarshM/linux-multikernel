#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify real selected MKTTY RX/last-close ordering and post-close delivery."""
import argparse
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle


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
        if len(events) != 9 or held['events'] != events[:2]:
            raise ValueError('missing or inconsistent MKTTY events')
        for index, event in enumerate(events, 1):
            irq = index in (1, 4, 9)
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != index or event['point'] != index
                    or event['cpu'] != (0 if irq else 2 if index == 3 else 1)
                    or event.get('hardirq') is not irq or event.get('vector') is not irq):
                raise ValueError('early free, wrong CPU role or non-native RX observation')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify(trace, revision):
    errors = verify_nested(trace, revision, qualification='native-tty')
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': expected exactly one event')
            return matches[0].start(), json.loads(matches[0][1])
        begin_at, begin = one('TTY_BEGIN')
        held_at, held = one('TTY_HELD')
        final_at, final = one('TTY_COMPLETE')
        health_at, health = one('TTY_CHILD_HEALTH')
        nonce = one('PING')[1]['nonce']
        child = one('CHILD_ALIVE')[1]
        if not begin_at < held_at < final_at < health_at:
            raise ValueError('MKTTY phases out of order')
        if any(v.get('nonce') != nonce for v in (begin, held, final, health)):
            raise ValueError('MKTTY nonce mismatch')
        if (any(v.get('taint') != 0 for v in (begin, final, health))
                or health.get('boot_id') != child['boot_id']
                or health.get('online_cpus') != child['physical_cpus']
                or any(v['state']['cookie'] != nonce for v in (held, final))):
            raise ValueError('post-reconnect child health/identity not preserved')
        errors += verify_records(held['state'], final['state'])
    except (KeyError, ValueError, TypeError) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='tty')
    errors += verify(args.trace.read_text(errors='replace'), args.revision)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native MKTTY selected RX/final close; ring writer retirement not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
