#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Native message-registry retirement, replacement and terminal rejection."""
import argparse
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle


def verify_records(held, final, mode):
    try:
        if mode not in ('replace', 'cleanup'):
            raise ValueError('unknown registry case')
        for key in ('cookie', 'handler', 'context', 'type_context'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('registry callback identity mismatch')
        if len({held[k] for k in ('handler', 'context', 'type_context')}) != 3:
            raise ValueError('registry allocation identities alias')
        for value, finished in ((held, False), (final, True)):
            if (value.get('mode') != (1 if mode == 'replace' else 2)
                    or value.get('done') is not finished or value.get('released') is not finished
                    or value.get('registration_done') is not finished
                    or value.get('waiter_sleeping') is not (not finished)
                    or value.get('registrar_sleeping') is not (not finished)
                    or value.get('timed_out') is not False or value.get('overflow') is not False
                    or type(value.get('invocations')) is not int or value['invocations'] != 1
                    or type(value.get('consumed')) is not int or value['consumed'] != (2 if finished else 0)
                    or value.get('replacement_invocations') != int(finished and mode == 'replace')):
                raise ValueError('actual blocked retirement/registration or clean outcome missing')
        if final.get('registration_result') != (0 if mode == 'replace' else -108):
            raise ValueError('wrong registration result after retirement')
        events = final['events']
        count = 15 if mode == 'replace' else 14
        if len(events) != count or len(held['events']) != 5 or held['events'] != events[:5]:
            raise ValueError('missing or inconsistent registry checkpoints')
        if [e['seq'] for e in events] != list(range(1, count + 1)):
            raise ValueError('registry observation ordering invalid')
        points = {}
        for event in events:
            if any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu')):
                raise ValueError('invalid native integer fields')
            p = event['point']
            points.setdefault(p, []).append(event['seq'])
            irq = p in (1, 4, 8, 15)
            if (event.get('cpu') != (0 if irq else 2 if p == 9 else 1)
                    or event.get('hardirq') is not irq or event.get('vector') is not irq):
                raise ValueError('wrong CPU role or native interrupt provenance')
        required = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14}
        if mode == 'replace':
            required.add(15)
        if set(points) != required or any(len(v) != (2 if p == 8 else 1) for p, v in points.items()):
            raise ValueError('wrong registry checkpoint multiplicity')
        def order(*args):
            seq = [points[p][0] for p in args]
            if seq != sorted(seq):
                raise ValueError('premature context reclamation or handler replacement')
        order(1, 12, 2, 3, 9, 4, 5, 6, 13, 7)
        order(12, 11, 9)
        order(13, 14)
        if points[8][0] <= points[4][0] or points[8][1] <= max(points[7][0], points[14][0]):
            raise ValueError('second delivery not proven after retirement/registration')
        if mode == 'replace':
            order(14, 15)
            if points[15][0] >= points[8][1]:
                raise ValueError('replacement callback not associated with second delivery')
    except (KeyError, TypeError, ValueError) as error:
        return [str(error)]
    return []


def verify(trace, revision, mode):
    terminal = mode == 'cleanup'
    errors = verify_nested(trace, revision, qualification='native-registry-' + mode,
                           terminal=terminal)
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': expected exactly one record')
            return matches[0].start(), json.loads(matches[0][1])
        held_at, held = one('REGISTRY_HELD')
        done_at, final = one('REGISTRY_COMPLETE')
        nonce = one('PING')[1]['nonce']
        if (not one('NESTED_POOL_RETIRED')[0] < held_at < done_at
                or held['mode'] != mode or final['mode'] != mode
                or any(v['nonce'] != nonce or v['state']['cookie'] != nonce for v in (held, final))):
            raise ValueError('registry request correlation mismatch')
        errors += verify_records(held['state'], final['state'], mode)
        if terminal:
            at, retained = one('REGISTRY_RETAINED')
            if (not done_at < at < one('NESTED_HOST_SURVIVED')[0]
                    or retained['assigned_cpus'] != one('NESTED_BEGIN')[1]['child_cpus']
                    or retained['status'] != 'active' or retained['reclamation'] != 'not-attempted'
                    or re.search(r'MK_X86_NESTED_(?:HALTED|UNLOADED)|all CPUs confirmed parked'
                                 r'|kexec_file: Unloading', trace)):
                raise ValueError('terminal cleanup cannot qualify normal instance reclamation')
        elif done_at >= trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked'):
            raise ValueError('registry lifetime phase must precede confirmed halt')
    except (KeyError, ValueError, TypeError) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--mode', choices=('replace', 'cleanup'), required=True)
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='registry')
    errors += verify(args.trace.read_text(errors='replace'), args.revision, args.mode)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native registry ' + args.mode + '; terminal cleanup never qualifies instance reclamation')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
