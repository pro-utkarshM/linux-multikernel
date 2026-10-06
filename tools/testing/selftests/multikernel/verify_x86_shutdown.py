#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private QEMU permit-rejection evidence; never a reclamation pass."""
import argparse
from pathlib import Path
import re
import uuid
from x86_lockdep import decode_record, verify_boundaries
from verify_x86_child import validate_bundle

MODES = ('panic-retention', 'contended-poweroff-retention')


def terminal_record(text):
    matches = re.findall(r'^MK_X86_SHUTDOWN (.*)$', text, re.M)
    if len(matches) != 1 or text.strip() != 'MK_X86_SHUTDOWN ' + matches[0].strip():
        raise ValueError('missing, duplicate or damaged terminal debug-port record')
    return decode_record(matches[0])


def verify(text, debug, mode, revision):
    errors = verify_boundaries(text, 'BEGIN', 'HOST_SURVIVED', 'CHILD_REPLY',
                               terminal=True, before='TERMINATION_REQUEST')
    names = ('BEGIN', 'CHILD_ALIVE', 'PING', 'CHILD_REPLY', 'SHUTDOWN_BEFORE',
             'TERMINATION_REQUEST', 'SHUTDOWN_OBSERVED', 'CONSOLE_CLOSED',
             'SHUTDOWN_RETAINED', 'HOST_SURVIVED', 'PASS')
    records, positions = {}, {}
    try:
        if mode not in MODES:
            raise ValueError('unsupported permit-rejection lane')
        for name in names:
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', text, re.M))
            if len(matches) != 1:
                raise ValueError(f'{name}: expected one record')
            records[name] = decode_record(matches[0][1])
            positions[name] = matches[0].start()
        if list(positions.values()) != sorted(positions.values()):
            raise ValueError('permit-rejection events out of order')
        begin, child, host = (records[name] for name in ('BEGIN', 'CHILD_ALIVE', 'HOST_SURVIVED'))
        groups = [begin.get(key) for key in ('host_cpus', 'child_cpus', 'spare_cpus')]
        if (any(not isinstance(group, list) or len(group) != 2 for group in groups)
                or any(type(cpu) is not int or cpu < 0 for group in groups for cpu in group)
                or len(set(sum(groups, []))) != 6):
            raise ValueError('physical CPU groups must be disjoint pairs')
        if not isinstance(revision, str) or not re.fullmatch('[0-9a-f]{40}', revision) or begin.get('revision') != revision:
            raise ValueError('unpinned kernel source')
        if (type(child.get('pid')) is not int or child['pid'] != 1 or child.get('instance') != 1
                or child.get('online') != '0-1' or child.get('physical_cpus') != groups[1]
                or not child.get('release') or host.get('online') != '0-1'
                or uuid.UUID(child['boot_id']) == uuid.UUID(host['boot_id'])):
            raise ValueError('child/host identity or topology mismatch')
        nonce = records['PING'].get('nonce')
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{16}', nonce):
            raise ValueError('missing nonce')
        for name in ('CHILD_REPLY', 'TERMINATION_REQUEST', 'SHUTDOWN_OBSERVED', 'CONSOLE_CLOSED'):
            if records[name].get('nonce') != nonce:
                raise ValueError(f'{name}: nonce mismatch')
        if records['TERMINATION_REQUEST'].get('mode') != mode:
            raise ValueError('wrong termination request')
        observed = records['SHUTDOWN_OBSERVED']
        if terminal_record(debug) != observed:
            raise ValueError('serial acknowledgment does not match actual debug-port output')
        contended = int(mode == 'contended-poweroff-retention')
        required = dict(instance=1, notify=0, panic=1-contended, kexec=0, observed=1,
                        busy=contended, active=contended, valid=contended, overflow=0, point=contended)
        if any(type(observed.get(key)) is not int or observed[key] != value for key, value in required.items()):
            raise ValueError('terminal decision or controller-gate evidence invalid')
        before, after = records['SHUTDOWN_BEFORE'], records['SHUTDOWN_RETAINED']
        for sample in (before, after):
            allocation = sample['allocations']
            if (sample.get('owned_cpus') != groups[1] or sample.get('fail_cpu') != 2**64-1
                    or sample.get('failures') != 0 or allocation.get('state') != 3
                    or allocation.get('pool_size') != 536870912
                    or any(not isinstance(allocation.get(key), str)
                           or not re.fullmatch('[0-9a-f]+', allocation[key])
                           or not int(allocation[key], 16)
                           for key in ('image', 'ring', 'ring_phys', 'control', 'context', 'pool'))):
                raise ValueError('resources absent, changed ownership, or confirmation injection enabled')
        if (before['allocations'] != after['allocations'] or after.get('mode') != mode
                or after.get('status') != 'active' or after.get('exec_errno') != 16
                or after.get('unload_errno') != 16 or after.get('destroy_status') != 'failed'):
            raise ValueError('unsafe operation accepted or resources changed')
        tx = after.get('destroy_transaction')
        refusals = list(re.finditer(r"Overlay tx" + str(tx) + r": Failed to remove instance 'native-child': -16\b", text))
        if (type(tx) is not int or tx <= 0 or len(refusals) != 1
                or not positions['CONSOLE_CLOSED'] < refusals[0].start() < positions['SHUTDOWN_RETAINED']):
            raise ValueError('missing specific post-close kernel destruction refusal')
        if records['PASS'].get('slice') != 'shutdown-permit-rejection':
            raise ValueError('wrong qualification slice')
        for match in re.finditer(r'\bMK_X86_NATIVE (.*)$', text, re.M):
            checkpoint = decode_record(match[1])
            if checkpoint.get('instance') == 1 and checkpoint.get('point') in (10, 11):
                raise ValueError('controller gate released or expired during rejection lane')
        # Expected child sysrq panic may precede observation; host panic never may.
        for panic in re.finditer('Kernel panic - not syncing:', text):
            if mode != 'panic-retention' or not positions['TERMINATION_REQUEST'] < panic.start() < positions['SHUTDOWN_OBSERVED']:
                raise ValueError('unexpected panic outside child termination interval')
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        errors.append(str(error))
    if re.search(r'MK_X86_(?:FAIL|HALTED|UNLOADED|CONFIRM_FAULT_CLEAR|TEST_CONFIRM_FAIL)\b'
                 r'|all CPUs confirmed parked|Sent NMI to|WARNING:|BUG:|Oops:|general protection fault'
                 r'|detected (?:expedited )?stalls|watchdog:.*lockup|fault while parked'
                 r'|rcu:.*(?:self-detected stall|kthread starved)', text, re.I):
        errors.append('recovery, settlement, injected confirmation failure or kernel fault')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--debug', type=Path, required=True)
    parser.add_argument('serial', type=Path)
    args = parser.parse_args()
    errors = validate_bundle(args.bundle, args.revision)
    errors += verify(args.serial.read_text(), args.debug.read_text(), args.mode, args.revision)
    for error in errors:
        print('FAIL:', error)
    if errors:
        raise SystemExit(1)
    print('PASS: shutdown permit rejected, resources retained; no reclamation claim')


if __name__ == '__main__':
    main()
