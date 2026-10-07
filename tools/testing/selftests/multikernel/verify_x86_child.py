#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify only the executing-child boot slice, not concurrency qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
from x86_lockdep import REQUIRED_CONFIG, decode_record, verify_boundaries

HALT_MODES = ('requested', 'force', 'halt', 'poweroff', 'reboot')
HALT_LANES = HALT_MODES + tuple(mode + '-retain' for mode in HALT_MODES) + ('mailbox-timeout',)


def verify_mailbox(trace, events, positions, child, nonce):
    errors = []
    if re.search(r'MK_X86_TEST_CONFIRM_FAIL|MK_X86_CONFIRM_FAULT_CLEAR|Sent NMI'
                 r'|all CPUs confirmed parked|MK_X86_(?:HALTED|UNLOADED|RETAINED) ', trace):
        errors.append('mailbox timeout lane contains injection, recovery or reclamation')
    try:
        before, after = events['MAILBOX_BEFORE'], events['MAILBOX_RETAINED']
        old, new = before['mailbox'], after['mailbox']
        allocations = before['allocations']
        for sample in (before, after):
            if (sample['allocations'] != allocations or sample['owned_cpus'] != child
                    or type(sample['fail_cpu']) is not int or sample['fail_cpu'] != 2**64-1
                    or type(sample['failures']) is not int or sample['failures'] != 0):
                errors.append('allocations/ownership changed or early failure injection enabled')
        pointers = ('image', 'ring', 'ring_phys', 'control', 'context', 'pool')
        if (allocations['state'] != 3 or allocations['pool_size'] != 536870912
                or any(not isinstance(allocations[key], str)
                       or not re.fullmatch(r'[0-9a-fA-F]+', allocations[key])
                       or not int(allocations[key], 16) for key in pointers)):
            errors.append('active Image, ring, control or pool allocation missing')
        initial = dict(used=0, cpu=2**64-1, result=0, retry=0, repark=0,
                       elapsed_us=0, selected_state=0, pool_state=0, tracked=0, tracked_count=2)
        expected = dict(used=1, result=-110, retry=-16, repark=-16,
                        selected_state=4, pool_state=4, tracked=1, tracked_count=2)
        for record, fields in ((old, initial), (new, expected)):
            if any(type(record[key]) is not int or record[key] != value
                   for key, value in fields.items()):
                errors.append('mailbox admission, quarantine, tracking or native refusal mismatch')
        if (type(new['cpu']) is not int or new['cpu'] not in child
                or type(new['elapsed_us']) is not int
                or not 1_000_000 <= new['elapsed_us'] <= 30_000_000):
            errors.append('wrong physical CPU or native timeout not observed')
        for key in ('instance_slot', 'instance_park', 'pool_slot', 'pool_park', 'pool_cr3'):
            if (not isinstance(old[key], str) or not re.fullmatch(r'[0-9a-fA-F]+', old[key])
                    or not int(old[key], 16) or new[key] != old[key]):
                errors.append('mailbox allocation changed or missing: ' + key)
        if (old['instance_slot'] != allocations['context']
                or events['MAILBOX_TIMEOUT']['mailbox'] != new
                or events['MAILBOX_TIMEOUT']['nonce'] != nonce
                or events['CONSOLE_CLOSED']['nonce'] != nonce):
            errors.append('mailbox result not correlated or not retained')
        native = list(re.finditer(
            r'mk_spawn: confirm parked: CPU \(APIC ([0-9]+)\) unconfirmed on slot '
            r'((?:0x)?[0-9a-fA-F]+); quarantined until host reboot', trace))
        if (len(native) != 1 or not positions[4] < native[0].start() < positions[5]
                or int(native[0][1]) != new['cpu']
                or int(native[0][2], 16) != int(new['instance_slot'], 16)):
            errors.append('no unique native mailbox timeout for the selected CPU/slot')
        transaction = after['destroy_transaction']
        refusal = list(re.finditer(r'Overlay tx' + re.escape(str(transaction))
                                  + r": Failed to remove instance 'native-child': -16\b", trace))
        if (type(transaction) is not int or transaction <= 0 or len(refusal) != 1
                or not positions[6] < refusal[0].start() < positions[7]
                or after['status'] != 'active' or after['destroy_status'] != 'failed'
                or type(after['exec_errno']) is not int or after['exec_errno'] != 16
                or type(after['unload_errno']) is not int or after['unload_errno'] != 16):
            errors.append('execute/unload/destruction refusal not established')
    except (KeyError, ValueError, TypeError, AttributeError):
        errors.append('invalid mailbox timeout evidence')
    if (events['HOST_SURVIVED'].get('online') != '0-1'
            or events['PASS'].get('slice') != 'mailbox-timeout-retention'):
        errors.append('host topology or mailbox qualification slice mismatch')
    return errors


def verify(trace, halt='requested', expected_revision=None):
    if halt not in HALT_LANES:
        return ['unsupported halt lane']
    mode = halt.removesuffix('-retain')
    retaining = halt.endswith('-retain')
    mailbox = halt == 'mailbox-timeout'
    errors = verify_boundaries(trace, 'BEGIN', 'HOST_SURVIVED',
                               'MAILBOX_TIMEOUT' if mailbox else 'CHILD_REPLY',
                               terminal=mailbox, before='CONSOLE_CLOSED' if mailbox else None)
    names = ('BEGIN', 'CHILD_ALIVE', 'PING', 'CHILD_REPLY', 'HALTED',
             'UNLOADED', 'HOST_SURVIVED', 'PASS')
    if mailbox:
        names = ('BEGIN', 'CHILD_ALIVE', 'PING', 'CHILD_REPLY', 'MAILBOX_BEFORE',
                 'MAILBOX_TIMEOUT', 'CONSOLE_CLOSED', 'MAILBOX_RETAINED', 'HOST_SURVIVED', 'PASS')
    events = {}
    positions = []
    if re.search(r'MK_X86_FAIL|Kernel panic - not syncing:|WARNING:|BUG:|Oops:'
                 r'|general protection fault|detected (?:expedited )?stalls'
                 r'|fault while parked|watchdog:.*lockup'
                 r'|rcu:.*(?:self-detected stall|kthread starved)', trace, re.I):
        errors.append('failure, panic or kernel diagnostic fault in native trace')
    for name in names:
        matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
        if len(matches) != 1:
            errors.append(f'{name}: expected exactly one event, got {len(matches)}')
            continue
        positions.append(matches[0].start())
        try:
            event = decode_record(matches[0][1])
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
    if (not isinstance(expected_revision, str)
            or not re.fullmatch(r'[0-9a-f]{40}', expected_revision)
            or begin.get('revision') != expected_revision):
        errors.append('missing or mismatched externally pinned source revision')
    if (type(child.get('pid')) is not int or type(child.get('instance')) is not int
            or child.get('pid') != 1 or child.get('instance') != 1
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
    if (not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{16}', nonce)
            or events['CHILD_REPLY'].get('nonce') != nonce):
        errors.append('missing fresh correlated child reply')
    if mailbox:
        if errors:
            return errors
        return verify_mailbox(trace, events, positions, groups[1], nonce)
    confirm = trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked')
    if confirm < positions[3] or confirm >= positions[4]:
        errors.append('no native all-CPU parked confirmation before settlement')
    captures = list(re.finditer(r'^MK_X86_CHILD_CAPTURED (.*)$', trace, re.M))
    try:
        if len(captures) != 1 or not confirm < captures[0].start() < positions[4]:
            raise ValueError('missing final child capture after confirmation')
        captured = json.loads(captures[0][1])
        if (captured.get('nonce') != nonce or type(captured.get('pending_bytes')) is not int
                or captured['pending_bytes'] != 0):
            raise ValueError('incomplete or uncorrelated final child capture')
    except (ValueError, TypeError) as error:
        errors.append(str(error))
    if events['HALTED'].get('mode') != halt:
        errors.append('halt lane mismatch')
    nmis = list(re.finditer(r'Sent NMI to ([0-9]+) CPUs in instance 1\b', trace))
    injection = -1
    if mode == 'force' or retaining:
        if not any(positions[3] < nmi.start() < confirm and nmi[1] == '2' for nmi in nmis):
            errors.append('no force-stop NMI to both assigned CPUs before settlement')
    elif any(positions[3] < nmi.start() < confirm for nmi in nmis):
        errors.append('healthy nonforce lane contains forced settlement')
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
                    or type(cpu) is not int or cpu not in groups[1] or before != after
                    or before.get('state') != 3 or before.get('pool_size') != 536870912
                    or any(not int(before[key], 16) for key in pointers)):
                errors.append('failed confirmation did not retain ownership/allocations or refuse reclaim')
            transaction = event.get('destroy_transaction')
            refusal = re.search(r'Overlay tx' + str(transaction)
                                + r": Failed to remove instance 'native-child': -16\b", trace)
            if (type(transaction) is not int or transaction <= 0 or not refusal):
                errors.append('no kernel destruction refusal for the specific transaction')
            fault = re.search(r'^.*?\bMK_X86_TEST_CONFIRM_FAIL phys=' + str(cpu)
                              + r'[ \t]*\r?$', trace, re.M)
            injection = fault.start() if fault else -1
            if (not positions[3] < injection < retained[0].start() < cleared[0].start() < confirm
                    or json.loads(cleared[0][1]).get('cpu') != cpu):
                errors.append('missing actual fault injection followed by bounded recovery')
            if refusal and not injection < refusal.start() < retained[0].start():
                errors.append('destruction refusal outside failed-retention interval')
            requests = list(re.finditer(r'^MK_X86_RETENTION_HALT_REQUEST (.*)$', trace, re.M))
            if (len(requests) != 1 or json.loads(requests[0][1]).get('mode') != mode
                    or not positions[3] < requests[0].start() < injection):
                errors.append('wrong initial halt path in the retention lane')
            initial_nmis = [nmi for nmi in nmis if positions[3] < nmi.start() < cleared[0].start()]
            if mode == 'force':
                if (len(initial_nmis) != 1 or initial_nmis[0][1] != '2'
                        or initial_nmis[0].start() >= injection):
                    errors.append('initial retention halt was not forced')
            elif initial_nmis:
                errors.append('nonforce retention lane started with forced halt')
            recovery_nmis = [nmi for nmi in nmis if cleared[0].start() < nmi.start() < confirm]
            if len(recovery_nmis) != 1 or recovery_nmis[0][1] != '2':
                errors.append('no distinct post-clear recovery NMI to both assigned CPUs')
            observed = list(re.finditer(r'^MK_X86_CONFIRM_FAILURE_OBSERVED (.*)$', trace, re.M))
            if len(observed) != 1:
                errors.append('missing worker failed-probe observation')
            else:
                counter = json.loads(observed[0][1])
                if (type(counter.get('before')) is not int or type(counter.get('after')) is not int
                        or not 0 <= counter['before'] < counter['after']
                        or counter.get('cpu') != cpu
                        or not injection < observed[0].start() < retained[0].start()):
                    errors.append('invalid worker failed-probe observation')
        except (KeyError, ValueError, TypeError, AttributeError):
            errors.append('invalid retention evidence')
    if mode in ('halt', 'poweroff', 'reboot'):
        requests = list(re.finditer(r'^MK_X86_TERMINATION_REQUEST (.*)$', trace, re.M))
        try:
            if (len(requests) != 1 or json.loads(requests[0][1]).get('mode') != mode
                    or not positions[3] < requests[0].start() < (injection if retaining else confirm)):
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


def validate_bundle(bundle, expected_revision):
    try:
        if not REQUIRED_CONFIG <= set((bundle / 'kernel.config').read_text().splitlines()):
            return ['strict lockdep build configuration missing']
        provenance = json.loads((bundle / 'provenance.json').read_text())
        proof = json.loads((bundle / 'mk-x86-build.json').read_text())
        files = {'.config': 'kernel.config', 'vmlinux': 'rootfs/payload/vmlinux',
                 'arch/x86/boot/bzImage': 'bzImage'}
        if (provenance.get('kernel_revision') != expected_revision
                or proof.get('revision') != expected_revision
                or proof.get('schema') != 1 or proof.get('build_exit') != 0
                or set(proof.get('artifacts', {})) != set(files)):
            return ['frozen bundle/build provenance does not match the external source pin']
        for name, path in files.items():
            with (bundle / path).open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != proof['artifacts'][name]:
                return ['frozen binary/config differs from build-time provenance: ' + name]
        result = subprocess.run(['sha256sum', '--check', '--quiet', 'SHA256SUMS'],
                                cwd=bundle, capture_output=True, text=True, timeout=60)
        if result.returncode:
            return ['frozen input manifest failed integrity check']
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return ['missing or invalid frozen input manifest/build provenance']
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--halt', choices=HALT_LANES,
                        default='requested')
    parser.add_argument('--revision', required=True, help='independently pinned full source commit')
    parser.add_argument('--bundle', type=Path, required=True, help='immutable input bundle')
    args = parser.parse_args()
    errors = validate_bundle(args.bundle, args.revision)
    errors += verify(args.trace.read_text(errors='replace'), halt=args.halt,
                     expected_revision=args.revision)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        if args.halt == 'mailbox-timeout':
            print('PASS: real mailbox timeout retained resources; recovery/reclamation not qualified')
        else:
            print(f'PASS: executing-child {args.halt} halt; worker/lifetime races not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
