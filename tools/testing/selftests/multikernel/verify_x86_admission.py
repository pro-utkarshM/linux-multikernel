#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify actual process admission/timeout evidence, not IRQ retirement."""
import argparse
import json
from pathlib import Path
import re

from verify_x86_nested import verify as verify_nested, validate_nested_bundle


def verify(trace, expected_revision=None):
    errors = verify_nested(trace, expected_revision, admission=True)
    records, native = [], []
    for match in re.finditer(r'MK_X86_(\w+) (\{[^\n]*\})', trace):
        try:
            value = json.loads(match[2])
            if not isinstance(value, dict):
                raise ValueError('not an object')
        except ValueError:
            errors.append('malformed evidence record')
            continue
        records.append((match[1], value, match.start()))
        if match[1] == 'NATIVE' and value.get('instance') == 1:
            native.append(value)
    fields = ('seq', 'point', 'request', 'cpu', 'result', 'operation')
    if any(any(type(e.get(k)) is not int for k in fields) for e in native):
        return errors + ['invalid native checkpoint fields']
    if (len({e['seq'] for e in native}) != len(native)
            or any(e['seq'] <= 0 or e['point'] == 11 for e in native)):
        errors.append('duplicate native sequence or checkpoint timeout')
    native.sort(key=lambda e: e['seq'])
    try:
        def one(name, mode=None):
            found = [v for n, v, _ in records if n == name
                     and (mode is None or v.get('mode') == mode)]
            if len(found) != 1:
                raise ValueError(f'{name}/{mode}: expected exactly one record')
            return found[0]

        begin = one('NESTED_BEGIN')
        child, spare = begin['child_cpus'], begin['spare_cpus']
        nonce = one('PING')['nonce']
        marks = [(n, v, p) for n, v, p in records if n.startswith('ADMISSION_')]
        if any(v.get('nonce') != nonce for _, v, _ in marks):
            raise ValueError('admission nonce mismatch')
        expected_names = []
        for mode in ('controller-first', 'worker-first'):
            expected_names += [('ADMISSION_BEGIN', mode), ('ADMISSION_HELD', mode),
                               ('ADMISSION_REJECTED' if mode == 'controller-first'
                                else 'ADMISSION_CONTROLLER_WAITING', mode),
                               ('ADMISSION_CONTROLLER_DONE', mode),
                               ('ADMISSION_RETIRED', mode), ('ADMISSION_REMOVED', mode),
                               ('ADMISSION_SETTLED', mode)]
        expected_names += [('ADMISSION_BEGIN', 'timeout-drain'),
                           ('ADMISSION_HELD', 'timeout-drain'),
                           ('ADMISSION_TIMEOUT_RETAINED', None),
                           ('ADMISSION_DRAIN_WAITING', None), ('ADMISSION_RELEASE_REQUEST', None),
                           ('ADMISSION_COMPLETE', None)]
        if [(n, v.get('mode')) for n, v, _ in marks] != expected_names:
            raise ValueError('missing, extra or reordered admission phase markers')
        retired_at = [p for n, _, p in records if n == 'NESTED_POOL_RETIRED']
        halted_at = [p for n, _, p in records if n == 'NESTED_HALTED']
        if (len(retired_at) != 1 or len(halted_at) != 1
                or not retired_at[0] < marks[0][2] < marks[-1][2] < halted_at[0]):
            raise ValueError('admission phase lies outside prerequisite/settlement boundaries')

        def checkpoint(point, request=None, cpu=None, operation=None, result=0):
            found = [e for e in native if e['point'] == point
                     and (request is None or e['request'] == request)
                     and (cpu is None or e['cpu'] == cpu)
                     and (operation is None or e['operation'] == operation)
                     and e['result'] == result]
            if len(found) != 1:
                raise ValueError(f'checkpoint {point}/{request}/{cpu}: missing or ambiguous')
            return found[0]

        def order(*events):
            seq = [e['seq'] for e in events]
            if seq != sorted(set(seq)):
                raise ValueError('native checkpoint ordering mismatch')

        def observed(event):
            if not isinstance(event, dict) or any(type(event.get(k)) is not int for k in fields):
                raise ValueError('invalid debugfs observation')
            actual = [e for e in native if e['seq'] == event['seq']]
            if len(actual) != 1 or any(actual[0][k] != event[k] for k in fields):
                raise ValueError('debugfs observation not correlated with native event')
            return actual[0]

        def transaction(value, status='applied'):
            if (value.get('status') != status or type(value.get('transaction')) is not int
                    or value['transaction'] <= 0):
                raise ValueError('actual overlay result missing')

        def retired(value, owned):
            if any(value.get(k) != expected for k, expected in
                   (('owned_cpus', owned), ('online_cpus', owned), ('pool_cpus', []),
                    ('chunks', []), ('slot', '0'), ('park', '0'))):
                raise ValueError('child ownership or local park retirement mismatch')

        used_requests = set()
        def worker(request, cpu, operation, status=0, busy=False):
            if request <= 0 or request in used_requests:
                raise ValueError('zero or reused CPU resource request')
            used_requests.add(request)
            entered = checkpoint(4 if busy else 2, request, cpu, operation, status if busy else 0)
            before = checkpoint(3, request, cpu, operation, status)
            sent = checkpoint(5, request, cpu, operation)
            order(entered, before, sent)
            if busy and any(e['point'] == 2 and e['request'] == request for e in native):
                raise ValueError('rejected worker acquired mutation lock')
            return entered, before, sent

        last = 0
        for mode, point in (('controller-first', 1), ('worker-first', 2)):
            if one('ADMISSION_BEGIN', mode).get('cpu') != child[-1]:
                raise ValueError('wrong admission CPU')
            held = one('ADMISSION_HELD', mode)
            enter = observed(held['event'])
            if (held.get('active') is not True or held.get('point') != point
                    or enter['point'] != 9 or enter['result'] != point or enter['seq'] <= last):
                raise ValueError('actual active admission hold missing')
            leave = checkpoint(10, enter['request'], enter['cpu'], enter['operation'])
            done = one('ADMISSION_CONTROLLER_DONE', mode)
            transaction(done)
            ctl = checkpoint(1, done['transaction'], 0, 0)
            attempt = checkpoint(8, done['transaction'], 0, 0)
            if mode == 'controller-first':
                order(attempt, ctl, enter)
                rejected = one('ADMISSION_REJECTED', mode)
                transaction(rejected, 'failed')
                if (rejected.get('assigned_cpus') != child or rejected.get('pool_cpus') != spare):
                    raise ValueError('busy rejection changed parent ownership')
                busy = [e for e in native if e['point'] == 4 and enter['seq'] < e['seq'] < leave['seq']]
                if len(busy) != 1:
                    raise ValueError('correlated busy admission missing')
                events = worker(busy[0]['request'], child[-1], 8194, -16, busy=True)
                order(enter, *events, leave)
                candidates = [e for e in native if e['point'] == 2 and e['cpu'] == child[-1]
                              and e['operation'] == 8194 and e['seq'] > leave['seq']]
                if not candidates:
                    raise ValueError('explicit remove retry missing')
                removed_events = worker(candidates[0]['request'], child[-1], 8194)
                order(leave, *removed_events)
                owned = child
            else:
                waiting = one('ADMISSION_CONTROLLER_WAITING', mode)
                contended = checkpoint(12, done['transaction'], 0, 0)
                if waiting.get('active') is not True or observed(waiting['event']) != contended:
                    raise ValueError('controller was not observed blocked')
                removed_events = worker(enter['request'], child[-1], 8194)
                order(removed_events[0], enter, attempt, contended, leave, ctl)
                order(leave, removed_events[1])
                owned = child[:-1]
            retirement = one('ADMISSION_RETIRED', mode)
            transaction(retirement)
            retired(retirement, owned)
            if retirement['transaction'] == done['transaction']:
                raise ValueError('controller and retirement transactions aliased')
            removed = one('ADMISSION_REMOVED', mode)
            transaction(removed)
            if (removed.get('assigned_cpus') != child[:-1]
                    or removed.get('pool_cpus') != sorted(spare + child[-1:])):
                raise ValueError('CPU removal not settled')
            adds = [e for e in native if e['point'] == 2 and e['cpu'] == child[-1]
                    and e['operation'] == 8193 and e['seq'] > removed_events[-1]['seq']]
            if not adds:
                raise ValueError('successful CPU re-add missing')
            added = worker(adds[0]['request'], child[-1], 8193)
            order(removed_events[-1], *added)
            settled = one('ADMISSION_SETTLED', mode)
            transaction(settled)
            retired(settled, child)
            if settled.get('assigned_cpus') != child:
                raise ValueError('parent ownership not restored')
            last = added[-1]['seq']

        held = one('ADMISSION_HELD', 'timeout-drain')
        enter = observed(held['event'])
        if (one('ADMISSION_BEGIN', 'timeout-drain').get('cpu') != spare[0]
                or held.get('active') is not True or held.get('point') != 3
                or enter['point'] != 9 or enter['result'] != 3):
            raise ValueError('pre-ACK timeout hold missing')
        entered, before, ack = worker(enter['request'], spare[0], 8193)
        if entered['seq'] <= last:
            raise ValueError('timeout case reused earlier worker')
        leave = checkpoint(10, enter['request'], spare[0], 8193)
        release = one('ADMISSION_RELEASE_REQUEST')
        if (any(type(release.get(key)) is not int or release[key] != enter[key]
                for key in ('request', 'cpu'))):
            raise ValueError('lockdep pre-release marker does not match held worker')
        release_at = [p for n, _, p in records if n == 'ADMISSION_RELEASE_REQUEST'][0]
        leave_at = [p for n, v, p in records if n == 'NATIVE' and v.get('instance') == 1
                    and v.get('seq') == leave['seq']][0]
        if release_at >= leave_at:
            raise ValueError('lockdep pre-release marker follows actual worker release')
        waiting = one('ADMISSION_DRAIN_WAITING')
        closed = observed(waiting['closed'])
        drained = checkpoint(7)
        if (waiting.get('active') is not True or observed(waiting['held']) != enter
                or closed['point'] != 6 or waiting.get('drain_sleeping') is not True):
            raise ValueError('actual quiescence wait missing')
        order(entered, before, enter, closed, leave, ack, drained)
        retained = one('ADMISSION_TIMEOUT_RETAINED')
        transaction(retained, 'failed')
        owned = sorted(child + spare[:1])
        if (retained.get('assigned_cpus') != owned or retained.get('pool_cpus') != spare[1:]
                or retained.get('unload_errno') != 16 or retained.get('instance_status') != 'active'
                or type(retained.get('elapsed_ms')) is not int or retained['elapsed_ms'] < 9000
                or not re.search(r'Failed to apply overlay transaction '
                                 + str(retained['transaction']) + r': -110\b', trace)):
            raise ValueError('real timeout and provisional retention not proven')
        retired(retained['child'], owned)
        complete = one('ADMISSION_COMPLETE')
        if complete.get('status') != 'loaded' or complete.get('assigned_cpus') != owned:
            raise ValueError('shutdown did not settle all assigned CPUs')
    except (KeyError, IndexError, TypeError, ValueError) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--snapshots', action='store_true', help='require native kernfs contention/retry evidence')
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='admission')
    errors += verify(args.trace.read_text(errors='replace'), args.revision)
    if args.snapshots:
        from verify_x86_snapshot import verify as verify_snapshots
        errors += verify_snapshots(args.trace.read_text(errors='replace'))
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native process admission and timeout drain; IRQ retirement not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
