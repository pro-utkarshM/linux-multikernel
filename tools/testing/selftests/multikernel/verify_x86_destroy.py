#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify persistent allocation reclamation after a real sender's last put."""
import argparse
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle


def verify_records(held, final):
    try:
        for key in ('cookie', 'instance', 'image', 'ring', 'manifest', 'pool'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('destruction correlation/allocation identity mismatch')
        if len({held[k] for k in ('instance', 'image', 'pool')}) != 3 or held['ring'] == held['manifest']:
            raise ValueError('allocation identities alias')
        for state, done in ((held, False), (final, True)):
            if (state.get('released') is not done or state.get('sent') is not done
                    or state.get('failed') is not False or state.get('retired') is not True
                    or state.get('probed') is not True or type(state.get('send_result')) is not int
                    or state['send_result'] != 0 or type(state.get('probe_result')) is not int
                    or state['probe_result'] != -22):
                raise ValueError('unproven reference hold, pool retirement or lookup removal')
        events = final['events']
        if len(events) != 11 or held['events'] != events[:5]:
            raise ValueError('missing or inconsistent destruction events')
        for index, event in enumerate(events, 1):
            expected_cpus = {0} if index in (1, 7) else {2} if index == 6 else {1} if index < 6 else {0, 1, 2}
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != index or event['point'] != index
                    or event['cpu'] not in expected_cpus or event.get('hardirq') is not False
                    or event.get('irqs_off') is not (index == 2)):
                raise ValueError('early free, missing grace period or invalid release context')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify(trace, revision):
    errors = verify_nested(trace, revision, qualification='native-destroy')
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': expected exactly one event')
            return matches[0].start(), json.loads(matches[0][1])
        armed_at, armed = one('DESTROY_ARMED')
        held_at, held = one('DESTROY_HELD')
        final_at, final = one('DESTROY_COMPLETE')
        nonce = one('PING')[1]['nonce']
        if not (one('NESTED_HALTED')[0] < armed_at < one('NESTED_UNLOADED')[0]
                < held_at < final_at < one('NESTED_HOST_SURVIVED')[0]):
            raise ValueError('destruction must follow actual stop/unload and precede host-survival proof')
        if (any(v.get('nonce') != nonce or v['state']['cookie'] != nonce for v in (armed, held, final))
                or any(v.get('taint') != 0 for v in (armed, final))):
            raise ValueError('destruction taint/correlation failure')
        initial, before = armed['state'], held['state']
        if (initial['events'] != before['events'][:1]
                or any(initial.get(k) != before[k] for k in ('instance', 'image', 'ring', 'manifest', 'pool'))
                or any(initial.get(k) is not False for k in ('released', 'failed', 'retired', 'sent', 'probed'))):
            raise ValueError('sender reference not held before unload')
        groups = one('NESTED_BEGIN')[1]
        if (held.get('instance_absent') is not True or held.get('status') != 'applied'
                or type(held.get('transaction')) is not int or held['transaction'] <= 0
                or held.get('pool_cpus') != sorted(groups['child_cpus'] + groups['spare_cpus'])):
            raise ValueError('actual removal, transaction or pool CPU return missing')
        errors += verify_records(before, final['state'])
    except (KeyError, ValueError, TypeError) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--snapshots', action='store_true', help='require kernfs read/removal evidence')
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='destroy')
    errors += verify(args.trace.read_text(errors='replace'), args.revision)
    if args.snapshots:
        from verify_x86_snapshot import verify as verify_snapshots
        errors += verify_snapshots(args.trace.read_text(errors='replace'), removal=True)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native sender reference/removal/deferred reclamation; not DMA or physical proof')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
