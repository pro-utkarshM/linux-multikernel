# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed verifier for the modern QEMU lifecycle integration lane."""
import json
from pathlib import Path
import re
import sys


def verify(text, exit_status, mode, harts, cycles):
    if exit_status or mode not in ('graceful', 'halt', 'poweroff', 'reboot', 'panic'):
        raise ValueError('failed process or unsupported mode')
    if harts not in (1, 2) or not 1 <= cycles <= 50:
        raise ValueError('unsupported topology or cycle count')
    if re.search(r'MK_LIFECYCLE_FAIL|MK_CHILD_FAIL|WARNING:|BUG:|Oops:|'
                 r'KASAN:|UBSAN:|soft lockup|hung task', text):
        raise ValueError('guest failure or unexpected kernel diagnostic')
    if ('Kernel panic' in text or 'Call Trace:' in text) and mode != 'panic':
        raise ValueError('unexpected panic')
    if mode == 'panic' and ('Trigger a crash' not in text or 'Rebooting in 1 seconds' not in text):
        raise ValueError('panic timeout path not exercised')
    firmware = re.search(r'^OpenSBI v[^\r\n]+', text, re.MULTILINE)
    if not firmware:
        raise ValueError('no firmware identity')
    matches = list(re.finditer(r'^MK_LIFECYCLE_(\w+) ([^\n]*)$', text, re.MULTILINE))
    records = [(match[1], json.loads(match[2])) for match in matches]
    if [name for name, _ in records] != ['BEGIN'] + ['CHILD', 'STOPPED'] * cycles + ['PASS']:
        raise ValueError('missing, duplicate or out-of-order scenario')
    begin, final = records[0][1], records[-1][1]
    if (begin.get('mode') != mode or begin.get('cycles') != cycles or
            len(begin.get('harts', [])) != harts or len(set(begin['harts'])) != harts or
            final.get('mode') != mode or final.get('cycles') != cycles or
            final.get('host_alive') is not True):
        raise ValueError('wrong requested scope or host survival')
    if text.count('MK_CHILD_READY ') != cycles or text.count('MK_CHILD_PONG') != cycles:
        raise ValueError('actual child execution/roundtrip missing')
    boots = set()
    panic_windows = []
    for cycle in range(1, cycles + 1):
        child, stopped = records[2 * cycle - 1][1], records[2 * cycle][1]
        if (child.get('cycle') != cycle or stopped.get('cycle') != cycle or
                child.get('assigned') != begin['harts'] or stopped.get('harts') != begin['harts'] or
                child.get('ring_roundtrip') is not True or stopped.get('host_alive') is not True or
                not child.get('boot') or child['boot'] in boots or
                child['boot'] == begin.get('host_boot')):
            raise ValueError('incomplete ownership, stop or new-child evidence')
        evidence = stopped.get('hsm_trace', [])
        if not isinstance(evidence, list) or not all(isinstance(line, str) for line in evidence):
            raise ValueError('malformed raw HSM evidence')
        for hart in begin['harts']:
            if not any(re.search(r'mk_hsm_status:.*\bhart=' + str(hart) + r' state=1\b', line)
                       for line in evidence):
                raise ValueError('no raw STOPPED observation for assigned hart')
        start, end = matches[2 * cycle - 1].end(), matches[2 * cycle].start()
        interval = text[start:end]
        if mode == 'panic':
            action = interval.find('MK_CHILD_ACTION mode=panic')
            trigger = interval.find('Trigger a crash')
            panic = interval.find('Kernel panic')
            timeout = interval.find('Rebooting in 1 seconds')
            if not 0 <= action < trigger < panic < timeout:
                raise ValueError('cycle lacks ordered panic action and timeout evidence')
            panic_windows.append((start + action, end))
        boots.add(child['boot'])
    for diagnostic in re.finditer(r'Kernel panic|Call Trace:|Trigger a crash|Rebooting in 1 seconds', text):
        if not any(start <= diagnostic.start() < end for start, end in panic_windows):
            raise ValueError('panic evidence outside the requested cycle action interval')
    return {'result': 'PASS', 'firmware': firmware.group(0), 'mode': mode,
            'harts': harts, 'cycles': cycles}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]).read_text(errors='replace'),
                            int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
                            int(sys.argv[5])), sort_keys=True))
