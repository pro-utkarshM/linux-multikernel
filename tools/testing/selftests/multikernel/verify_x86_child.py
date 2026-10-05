#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify only the executing-child boot slice, not concurrency qualification."""
import argparse
import json
from pathlib import Path
import re
import uuid

HALT_MODES = ('requested', 'force', 'poweroff', 'reboot')
HALT_LANES = HALT_MODES + tuple(mode + '-retain' for mode in HALT_MODES)


def verify(trace, halt='requested'):
    if halt not in HALT_LANES:
        return ['unsupported halt lane']
    mode = halt.removesuffix('-retain')
    retaining = halt.endswith('-retain')
    errors = []
    names = ('BEGIN', 'CHILD_ALIVE', 'PING', 'CHILD_REPLY', 'HALTED',
             'UNLOADED', 'HOST_SURVIVED', 'PASS')
    events = {}
    positions = []
    if 'MK_X86_FAIL' in trace or 'Kernel panic - not syncing:' in trace:
        errors.append('failure or panic in native trace')
    for name in names:
        matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
        if len(matches) != 1:
            errors.append(f'{name}: expected exactly one event, got {len(matches)}')
            continue
        positions.append(matches[0].start())
        try:
            event = json.loads(matches[0][1])
            if not isinstance(event, dict):
                raise ValueError('event is not an object')
            events[name] = event
        except (ValueError, TypeError):
            errors.append(f'{name}: invalid JSON event')
    if len(events) != len(names):
        return errors
    if positions != sorted(positions):
        errors.append('native events out of lifecycle order')
    begin, child = events['BEGIN'], events['CHILD_ALIVE']
    groups = [begin.get(key) for key in ('host_cpus', 'child_cpus', 'spare_cpus')]
    if (any(not isinstance(group, list) or len(group) != 2 for group in groups)
            or any(type(cpu) is not int or cpu < 0 for group in groups
                   if isinstance(group, list) for cpu in group)):
        errors.append('expected two host, child and spare physical CPUs')
    elif len(set(sum(groups, []))) != 6:
        errors.append('physical CPU ownership groups overlap')
    if not re.fullmatch(r'[0-9a-f]{40}', str(begin.get('revision', ''))):
        errors.append('missing exact source revision')
    if (child.get('pid') != 1 or child.get('instance') != 1
            or child.get('online') != '0-1'
            or child.get('physical_cpus') != begin.get('child_cpus')
            or not child.get('release')):
        errors.append('child identity, secondary boot or physical ownership mismatch')
    for name in ('CHILD_ALIVE', 'HOST_SURVIVED'):
        try:
            uuid.UUID(events[name].get('boot_id', ''))
        except (ValueError, TypeError, AttributeError):
            errors.append(f'{name}: missing valid boot identity')
    if child.get('boot_id') == events['HOST_SURVIVED'].get('boot_id'):
        errors.append('host and child share boot identity')
    nonce = events['PING'].get('nonce')
    if (not re.fullmatch(r'[0-9a-f]{16}', str(nonce))
            or events['CHILD_REPLY'].get('nonce') != nonce):
        errors.append('missing fresh correlated child reply')
    confirm = trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked')
    if confirm < positions[3] or confirm >= positions[4]:
        errors.append('no native all-CPU parked confirmation before settlement')
    if events['HALTED'].get('mode', 'requested') != halt:
        errors.append('halt lane mismatch')
    if mode == 'force' or retaining:
        nmi = trace.find('Sent NMI to 2 CPUs in instance 1')
        if nmi < positions[3] or nmi >= confirm:
            errors.append('no force-stop NMI to both assigned CPUs before settlement')
    if retaining:
        retained = list(re.finditer(r'^MK_X86_RETAINED (.*)$', trace, re.M))
        cleared = list(re.finditer(r'^MK_X86_CONFIRM_FAULT_CLEAR (.*)$', trace, re.M))
        try:
            if len(retained) != 1 or len(cleared) != 1:
                raise ValueError('missing retention or recovery event')
            event = json.loads(retained[0][1])
            before, after = event['allocations_before'], event['allocations_after']
            cpu = event['fault_cpu']
            pointers = ('image', 'ring', 'ring_phys', 'control', 'context', 'pool')
            if (event.get('status') != 'active' or event.get('owned_cpus') != groups[1]
                    or event.get('unload_errno') != 16 or event.get('destroy_status') != 'failed'
                    or cpu not in groups[1] or before != after
                    or before.get('state') != 3 or before.get('pool_size') != 536870912
                    or any(not int(before[key], 16) for key in pointers)):
                errors.append('failed confirmation did not retain ownership/allocations or refuse reclaim')
            transaction = event.get('destroy_transaction')
            if (type(transaction) is not int or transaction <= 0
                    or not re.search(r'Overlay tx' + str(transaction)
                                     + r": Failed to remove instance 'native-child': -16\b", trace)):
                errors.append('no kernel destruction refusal for the specific transaction')
            fault = re.search(r'\bMK_X86_TEST_CONFIRM_FAIL phys=' + str(cpu) + r'\b', trace)
            injection = fault.start() if fault else -1
            if (not positions[3] < injection < retained[0].start() < cleared[0].start() < confirm
                    or json.loads(cleared[0][1]).get('cpu') != cpu):
                errors.append('missing actual fault injection followed by bounded recovery')
            if mode == 'force' and nmi >= injection:
                errors.append('initial retention halt was not forced')
            if mode != 'force':
                requests = list(re.finditer(r'^MK_X86_RETENTION_HALT_REQUEST (.*)$', trace, re.M))
                if (len(requests) != 1 or json.loads(requests[0][1]).get('mode') != mode
                        or not positions[3] < requests[0].start() < injection
                        or nmi < cleared[0].start()):
                    errors.append('wrong initial halt path in the retention lane')
        except (KeyError, ValueError, TypeError, AttributeError):
            errors.append('invalid retention evidence')
    if mode in ('poweroff', 'reboot'):
        requests = list(re.finditer(r'^MK_X86_TERMINATION_REQUEST (.*)$', trace, re.M))
        try:
            if (len(requests) != 1 or json.loads(requests[0][1]).get('mode') != mode
                    or not positions[3] < requests[0].start() < confirm):
                errors.append('missing matching child termination request')
        except (ValueError, TypeError, AttributeError):
            errors.append('invalid child termination request')
    for name, status in (('HALTED', 'loaded'), ('UNLOADED', 'ready')):
        if (events[name].get('status') != status
                or events[name].get('assigned_cpus') != begin.get('child_cpus')):
            errors.append(f'{name}: status or retained ownership mismatch')
    if events['HOST_SURVIVED'].get('online') != '0-1':
        errors.append('host topology changed unexpectedly')
    if events['PASS'].get('slice') != 'executing-child-boot':
        errors.append('wrong qualification slice')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--halt', choices=HALT_LANES,
                        default='requested')
    args = parser.parse_args()
    errors = verify(args.trace.read_text(errors='replace'), halt=args.halt)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print(f'PASS: executing-child {args.halt} halt; worker/lifetime races not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
