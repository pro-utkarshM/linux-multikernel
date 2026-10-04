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
    records = []
    for line in text.splitlines():
        if line.startswith('MK_LIFECYCLE_'):
            name, _, value = line.partition(' ')
            records.append((name.removeprefix('MK_LIFECYCLE_'), json.loads(value)))
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
    for cycle in range(1, cycles + 1):
        child, stopped = records[2 * cycle - 1][1], records[2 * cycle][1]
        if (child.get('cycle') != cycle or stopped.get('cycle') != cycle or
                child.get('assigned') != begin['harts'] or stopped.get('harts') != begin['harts'] or
                child.get('ring_roundtrip') is not True or stopped.get('host_alive') is not True or
                not child.get('boot') or child['boot'] in boots or
                child['boot'] == begin.get('host_boot')):
            raise ValueError('incomplete ownership, stop or new-child evidence')
        boots.add(child['boot'])
    return {'result': 'PASS', 'firmware': firmware.group(0), 'mode': mode,
            'harts': harts, 'cycles': cycles}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]).read_text(errors='replace'),
                            int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
                            int(sys.argv[5])), sort_keys=True))
