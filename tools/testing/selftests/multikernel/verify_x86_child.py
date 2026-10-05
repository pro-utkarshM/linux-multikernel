#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify only the executing-child boot slice, not concurrency qualification."""
import argparse
import json
from pathlib import Path
import re
import uuid


def verify(trace):
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
    args = parser.parse_args()
    errors = verify(args.trace.read_text(errors='replace'))
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: executing-child boot only; worker/lifetime races not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
