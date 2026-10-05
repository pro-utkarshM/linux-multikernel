#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify the nested pool prerequisite, never worker or IRQ race coverage."""
import argparse
import json
from pathlib import Path
import re
import uuid

from verify_x86_child import validate_bundle


def cpu_set(value, size=None):
    return (isinstance(value, list) and (size is None or len(value) == size)
            and all(type(cpu) is int and 0 <= cpu < (1 << 64) - 1 for cpu in value)
            and len(set(value)) == len(value) and value == sorted(value))


def verify(trace, expected_revision=None, *, admission=False):
    names = ('NESTED_BEGIN', 'CHILD_ALIVE', 'PING', 'CHILD_REPLY',
             'NESTED_POOL_READY', 'NESTED_CPU_RETURNED', 'NESTED_POOL_RETIRED',
             'NESTED_HALTED', 'NESTED_UNLOADED', 'NESTED_HOST_SURVIVED', 'NESTED_PASS')
    errors, events, positions = [], {}, {}
    if re.search(r'MK_X86_FAIL|Kernel panic - not syncing:|WARNING:|BUG:|Sent NMI to'
                 r'|general protection fault|Oops:|detected (?:expedited )?stalls'
                 r'|fault while parked'
                 r'|watchdog:.*lockup|rcu:.*(?:self-detected stall|kthread starved)',
                 trace, re.I):
        errors.append('fault, warning or forced recovery in prerequisite trace')
    for name in names:
        matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
        if len(matches) != 1:
            errors.append(f'{name}: expected exactly one event')
            continue
        positions[name] = matches[0].start()
        try:
            value = json.loads(matches[0][1])
            if not isinstance(value, dict):
                raise ValueError('not an object')
            events[name] = value
        except (ValueError, TypeError):
            errors.append(f'{name}: invalid event')
    if len(events) != len(names):
        return errors
    order = [positions[name] for name in names]
    if order != sorted(order):
        errors.append('prerequisite events out of order')
    begin, child = events['NESTED_BEGIN'], events['CHILD_ALIVE']
    groups = [begin.get(key) for key in ('host_cpus', 'child_cpus', 'spare_cpus')]
    if (not all(cpu_set(group, size) for group, size in zip(groups, (3, 3, 2)))
            or len(set(sum((group for group in groups if isinstance(group, list)), []))) != 8):
        errors.append('expected disjoint three-host/three-child/two-spare physical CPU sets')
        return errors
    assigned = groups[1]
    if (not isinstance(expected_revision, str)
            or not re.fullmatch(r'[0-9a-f]{40}', expected_revision)
            or begin.get('revision') != expected_revision):
        errors.append('missing or mismatched external source pin')
    if (type(child.get('pid')) is not int or child.get('pid') != 1
            or type(child.get('instance')) is not int or child.get('instance') != 1
            or child.get('online') != '0-2'
            or not cpu_set(child.get('physical_cpus'), 3)
            or child.get('physical_cpus') != assigned):
        errors.append('real three-CPU child identity missing')
    for name in ('CHILD_ALIVE', 'NESTED_HOST_SURVIVED'):
        try:
            uuid.UUID(events[name].get('boot_id', ''))
        except (ValueError, TypeError, AttributeError):
            errors.append(f'{name}: invalid boot identity')
    if child.get('boot_id') == events['NESTED_HOST_SURVIVED'].get('boot_id'):
        errors.append('host and child share boot identity')
    nonce = events['PING'].get('nonce')
    if (not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{16}', nonce)
            or events['CHILD_REPLY'].get('nonce') != nonce):
        errors.append('fresh child handshake missing')
    cpu = events['NESTED_POOL_READY'].get('cpu')
    if type(cpu) is not int or cpu != assigned[-1]:
        errors.append('wrong physical CPU selected for nested roundtrip')
    for name in ('NESTED_POOL_READY', 'NESTED_CPU_RETURNED', 'NESTED_POOL_RETIRED'):
        value = events[name]
        expected_owned = assigned[:-1] if name == 'NESTED_POOL_READY' else assigned
        expected_pool = [assigned[-1]] if name == 'NESTED_POOL_READY' else []
        if (value.get('nonce') != nonce or type(value.get('cpu')) is not int
                or value.get('cpu') != cpu
                or not cpu_set(value.get('owned_cpus'))
                or not cpu_set(value.get('online_cpus'))
                or not cpu_set(value.get('pool_cpus'))
                or value.get('owned_cpus') != expected_owned
                or value.get('online_cpus') != expected_owned
                or value.get('pool_cpus') != expected_pool):
            errors.append(f'{name}: ownership, online or request correlation mismatch')
    ready, retired = events['NESTED_POOL_READY'], events['NESTED_POOL_RETIRED']
    try:
        chunks = ready['chunks']
        if (not isinstance(chunks, list) or len(chunks) != 1
                or not isinstance(chunks[0], list) or len(chunks[0]) != 2
                or any(type(value) is not int for value in chunks[0])):
            raise ValueError('invalid pool chunk')
        base, size = chunks[0]
        if base <= 0 or base % 4096 or size != 16 * 1024 * 1024:
            raise ValueError('incorrect pool grant')
        for key in ('slot', 'park'):
            if (not isinstance(ready[key], str) or not re.fullmatch(r'[0-9a-f]+', ready[key])
                    or not base <= int(ready[key], 16) < base + size
                    or retired[key] != '0'):
                raise ValueError('park storage missing, out of grant, or not retired')
        if retired['chunks'] != []:
            raise ValueError('nested chunk retained')
    except (KeyError, ValueError, TypeError):
        errors.append('nested pool allocation/retirement not proven')
    returned = events['NESTED_CPU_RETURNED']
    for value in (returned, retired):
        if (type(value.get('transaction')) is not int or value['transaction'] <= 0
                or value.get('status') != 'applied'):
            errors.append('actual successful overlay transaction missing')
    if returned.get('transaction') == retired.get('transaction'):
        errors.append('CPU return and teardown reused the same transaction')
    confirmation = trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked')
    if not positions['NESTED_POOL_RETIRED'] < confirmation < positions['NESTED_HALTED']:
        errors.append('parent did not confirm all CPUs after nested park retirement')
    final_assigned = sorted(assigned + groups[2][:1]) if admission else assigned
    for name, state in (('NESTED_HALTED', 'loaded'), ('NESTED_UNLOADED', 'ready')):
        if events[name].get('status') != state or events[name].get('assigned_cpus') != final_assigned:
            errors.append(f'{name}: reusable state or retained ownership mismatch')
    if events['NESTED_HOST_SURVIVED'].get('online') != '0-2':
        errors.append('host topology not preserved')
    if events['NESTED_PASS'].get('slice') != ('native-admission' if admission else 'nested-pool-prerequisite'):
        errors.append('wrong qualification slice')
    return errors


def validate_nested_bundle(bundle, revision, *, profile='nested'):
    errors = validate_bundle(bundle, revision)
    try:
        provenance = json.loads((bundle / 'provenance.json').read_text())
        config = set((bundle / 'kernel.config').read_text().splitlines())
        required = {'CONFIG_MULTIKERNEL=y', 'CONFIG_DEBUG_FS=y',
                    'CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST=y'}
        if provenance.get('profile') != profile or not required <= config:
            errors.append('nested profile/observation configuration missing')
    except (OSError, ValueError, TypeError, AttributeError):
        errors.append('invalid nested profile/configuration')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision)
    errors += verify(args.trace.read_text(errors='replace'), expected_revision=args.revision)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: nested pool prerequisite; worker/IRQ races not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
