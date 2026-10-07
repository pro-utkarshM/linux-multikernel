# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed verifier for bounded injected HSM failures, not domain policy."""
import json
from pathlib import Path
import re
import sys
from verify_lifecycle import verify


def verify_fault(text, exit_status, mode, fault):
    supported = {'deny-primary': (1, 2, 3, 4), 'partial-start': (5,), 'stuck-stop': (7,)}
    if exit_status or mode not in supported or fault not in supported[mode]:
        raise ValueError('failed process or wrong injected scope')
    if re.search(r'MK_LIFECYCLE_FAIL|MK_CHILD_FAIL|WARNING:|BUG:|Oops:|KASAN:|UBSAN:|'
                 r'Kernel panic|Call Trace:|soft lockup|hung task', text):
        raise ValueError('unexpected guest diagnostic')
    if not re.search(r'^OpenSBI v', text, re.MULTILINE):
        raise ValueError('missing firmware identity')
    records = [(match[1], json.loads(match[2])) for match in
               re.finditer(r'^MK_LIFECYCLE_(\w+) ([^\n]*)$', text, re.MULTILINE)]
    if not records:
        raise ValueError('no scenario records')
    begin, final = records[0][1], records[-1][1]
    harts = begin.get('harts', [])
    if (begin.get('mode') != mode or begin.get('fault') != fault or begin.get('cycles') != 1 or
            len(harts) != 2 or len(set(harts)) != 2 or begin.get('images') != 'same' or
            final.get('mode') != mode or final.get('cycles') != 1 or final.get('host_alive') is not True):
        raise ValueError('wrong recorded scope')
    if mode == 'partial-start':
        result = verify(text, exit_status, mode, 2, 1)
        child = records[1][1]
        if len(child.get('online', [])) != 1:
            raise ValueError('partial child topology not exercised')
        if not re.search(r'MK_FW_REJECT mode=5 hart=(?:' + '|'.join(map(str, harts)) +
                         r') entry=0x[0-9a-f]+ error=-4\b', text):
            raise ValueError('secondary denial not injected')
        result['fault'] = fault
        return result
    if mode == 'deny-primary':
        if [kind for kind, _ in records] != ['BEGIN', 'REJECTED', 'PASS'] or 'MK_CHILD_READY' in text:
            raise ValueError('unexpected execution after primary rejection')
        rejection = records[1][1]
        expected = 22 if fault == 2 else 1
        firmware_error = -3 if fault == 2 else -4
        if (rejection.get('error') != expected or rejection.get('harts') != harts or
                rejection.get('cleanup') != 'ready' or rejection.get('host_alive') is not True):
            raise ValueError('wrong error or unsafe failure cleanup')
        if not re.search(r'MK_FW_REJECT mode=' + str(fault) + r' hart=(?:' + '|'.join(map(str, harts)) +
                         r') entry=0x[0-9a-f]+ error=' + str(firmware_error) + r'\b', text):
            raise ValueError('requested firmware rejection absent')
        evidence = rejection.get('hsm_trace', [])
        for hart in harts:
            if not any(re.search(r'mk_hsm_status:.*\bhart=' + str(hart) + r' state=1\b', line)
                       for line in evidence):
                raise ValueError('cleanup without STOPPED observation')
    else:
        if [kind for kind, _ in records] != ['BEGIN', 'CHILD', 'RETAINED', 'PASS']:
            raise ValueError('missing retained-resource scenario')
        child, retained = records[1][1], records[2][1]
        if (child.get('assigned') != harts or child.get('ring_roundtrip') is not True or
                child.get('active_unload_rejected') is not True or
                text.count('MK_CHILD_READY ') != 1 or text.count('MK_CHILD_PONG') != 1 or
                retained.get('harts') != harts or retained.get('state') != 'active' or
                retained.get('host_alive') is not True or retained.get('no_copy_or_start') is not True or
                retained.get('ownership_unchanged') is not True or
                retained.get('tracer_exercised') is not True or
                retained.get('rejected') != {'exec': 16, 'unload': 16, 'destroy': 'failed'} or
                final.get('retained_until_vm_shutdown') is not True):
            raise ValueError('missing containment, rejection or lifetime proof')
        transaction = retained.get('destroy_tx', '')
        if (not re.fullmatch(r'tx_\d+', transaction) or
                not re.search(r'Failed to apply overlay transaction ' +
                              transaction[3:] + r': -16\b', text)):
            raise ValueError('no correlated failed removal transaction')
        if not any(f'MK_FW_PENDING mode=7 hart={hart} actual=1 reported=3' in text for hart in harts):
            raise ValueError('permanent pending selector not exercised')
    return {'result': 'PASS', 'mode': mode, 'fault': fault, 'harts': harts}


if __name__ == '__main__':
    print(json.dumps(verify_fault(Path(sys.argv[1]).read_text(errors='replace'), int(sys.argv[2]),
                                 sys.argv[3], int(sys.argv[4])), sort_keys=True))
