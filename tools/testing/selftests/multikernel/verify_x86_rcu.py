#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Qualify one real vector callback versus native unregister/RCU, not all IRQs."""
import argparse
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle


def verify_records(held, final):
    try:
        for key in ('cookie', 'handler', 'context'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('callback identity or cookie mismatch')
        if held['handler'] == held['context']:
            raise ValueError('handler and context identity alias')
        for state, finished in ((held, False), (final, True)):
            if (state.get('done') is not finished or state.get('released') is not finished
                    or state.get('timed_out') is not False or state.get('overflow') is not False
                    or type(state.get('invocations')) is not int or state['invocations'] != 1
                    or type(state.get('consumed')) is not int or state['consumed'] != (2 if finished else 0)):
                raise ValueError('missing hold, retirement, consumption or clean gate result')
        if held.get('waiter_sleeping') is not True:
            raise ValueError('unregister not observed sleeping in actual grace period')
        if final.get('waiter_sleeping') is not False:
            raise ValueError('unregister waiter has not finished')
        events = final['events']
        if len(events) != 10 or held['events'] != events[:3]:
            raise ValueError('missing, extra or inconsistent native event')
        if [e['seq'] for e in events] != list(range(1, 11)):
            raise ValueError('native events out of order')
        if [e['point'] for e in held['events']] != [1, 2, 3]:
            raise ValueError('entered callback, unlink and grace-period entry missing')
        by_point = {}
        for event in events:
            if any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu')):
                raise ValueError('invalid native integer field')
            if any(type(event.get(k)) is not bool for k in ('hardirq', 'vector')):
                raise ValueError('invalid interrupt observation')
            point = event['point']
            by_point.setdefault(point, []).append(event)
            irq = point in (1, 4, 8)
            cpu = 0 if irq else 2 if point == 9 else 1
            if event['cpu'] != cpu or event['hardirq'] is not irq or event['vector'] is not irq:
                raise ValueError('wrong CPU role or native vector/hard-IRQ provenance')
        if set(by_point) != set(range(1, 10)) or any(len(v) != (2 if k == 8 else 1)
                                                    for k, v in by_point.items()):
            raise ValueError('wrong native checkpoint multiplicity')
        required = [by_point[p][0]['seq'] for p in (1, 2, 3, 9, 4, 5, 6, 7)]
        if required != sorted(required):
            raise ValueError('premature handler/context reclamation')
        consumes = [e['seq'] for e in by_point[8]]
        if consumes[0] <= by_point[4][0]['seq'] or consumes[1] <= by_point[7][0]['seq']:
            raise ValueError('post-unregister delivery not consumed after reclamation')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify(trace, revision):
    errors = verify_nested(trace, revision, qualification='native-rcu')
    records = []
    for name in ('RCU_HELD', 'RCU_COMPLETE'):
        matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
        if len(matches) != 1:
            return errors + [f'{name}: expected exactly one native observation']
        try:
            records.append((matches[0].start(), json.loads(matches[0][1])))
        except ValueError:
            return errors + ['invalid RCU record']
    try:
        ping = re.search(r'^MK_X86_PING (.*)$', trace, re.M)
        nonce = json.loads(ping[1])['nonce']
        retired = list(re.finditer(r'^MK_X86_NESTED_POOL_RETIRED ', trace, re.M))
        confirmed = trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked')
        if (len(retired) != 1 or not retired[0].start() < records[0][0] < records[1][0] < confirmed
                or any(value['nonce'] != nonce or value['state']['cookie'] != nonce for _, value in records)):
            return errors + ['RCU nonce or observation ordering mismatch']
        return errors + verify_records(records[0][1]['state'], records[1][1]['state'])
    except (KeyError, TypeError, ValueError):
        return errors + ['missing RCU identity']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='rcu')
    errors += verify(args.trace.read_text(errors='replace'), args.revision)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native IPI callback/unregister RCU; other lifetime cases not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
