# SPDX-License-Identifier: GPL-2.0-only
"""Private native manifest failure/retry lane, not firmware/cache proof."""
import json
from collections import Counter
from pathlib import Path
import re
import sys
from verify_lifecycle import verify
from verify_retention import release_control, loaded_extents


def verify_manifest(text, exit_status, mode, harts):
    expected = {'manifest-prepare': (1, 12), 'manifest-capacity': (2, 28)}
    if mode not in expected:
        raise ValueError('unsupported manifest fault')
    fault, error = expected[mode]
    pattern = r'^MK_LIFECYCLE_(MANIFEST_REJECTED|MANIFEST_RECOVERED|MANIFEST_RELEASED) ([^\n]*)\n?'
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if [match[1] for match in matches] != ['MANIFEST_REJECTED', 'MANIFEST_RECOVERED', 'MANIFEST_RELEASED']:
        raise ValueError('missing, duplicate or unordered manifest checks')
    rejected, recovered, released = [json.loads(match[2]) for match in matches]
    begin_match = re.search(r'^MK_LIFECYCLE_BEGIN ([^\n]*)$', text, re.MULTILINE)
    if not begin_match:
        raise ValueError('missing requested scope')
    begin = json.loads(begin_match[1])
    child = text.find('MK_LIFECYCLE_CHILD ')
    ready = text.find('MK_CHILD_READY ')
    stopped = text.find('MK_LIFECYCLE_STOPPED ')
    passed = text.find('MK_LIFECYCLE_PASS ')
    if not begin_match.end() < matches[0].start() < ready < child < matches[1].start() < stopped:
        raise ValueError('failure must precede child execution and recovery')
    if not stopped < matches[2].start() < passed:
        raise ValueError('release must follow stopped confirmation')
    if (rejected.get('error') != error or rejected.get('state') != 'loaded' or
            rejected.get('ownership_unchanged') is not True or
            not begin.get('host_boot') or rejected.get('host_boot') != begin['host_boot']):
        raise ValueError('wrong errno, state, ownership or host identity')
    raw = '\n'.join(line for line in text.splitlines()
                    if not line.startswith('MK_LIFECYCLE_'))
    guards = re.findall(r'MK_TEST_MANIFEST fault=(\d+) id=(\d+)', raw)
    guard_log = rejected.get('guard_log', '')
    if (guards != [(str(fault), '1')] or not guard_log or
            guard_log.strip() not in raw or
            f'MK_TEST_MANIFEST fault={fault} id=1' not in guard_log or
            f'Manifest finalization failed: -{error}; refusing start' not in guard_log or
            'MK_TEST_FREE id=1 ' in guard_log):
        raise ValueError('missing actual one-shot fault or premature resource release')
    for record in (rejected, recovered):
        trace = record.get('trace')
        if not isinstance(trace, list) or not all(isinstance(line, str) for line in trace):
            raise ValueError('missing trace window')
    before = '\n'.join(rejected['trace'])
    after = '\n'.join(recovered['trace'])
    if 'mk_copy:' not in before or 'mk_start:' in before:
        raise ValueError('failed manifest did not stop before hart start')
    if 'mk_copy:' not in after or 'mk_start:' not in after:
        raise ValueError('recovery did not positively exercise tracing')
    if after.rfind('mk_copy:') >= after.find('mk_start:'):
        raise ValueError('recovery started a hart before copies finished')
    for window in (before, after):
        pre_copy = window[:window.index('mk_copy:')]
        for hart in begin.get('harts', []):
            states = re.findall(r'mk_hsm_status:.*\bhart=' + re.escape(str(hart)) +
                                r' state=(-?\d+)\b', pre_copy)
            if not states or states[-1] != '1':
                raise ValueError('latest pre-copy observation is not STOPPED')
    release_control(released)
    release_log = released.get('release_log', '')
    frees = r'MK_TEST_FREE id=1 kind=\w+ phys=[0-9a-f]+ size=\d+ pool=[0-9a-f]+'
    if (released['resources']['owned'] != harts or not release_log or
            release_log.strip() not in raw or
            Counter(re.findall(frees, raw)) != Counter(re.findall(frees, release_log))):
        raise ValueError('uncorrelated allocation release outside stopped cleanup')
    placements = loaded_extents(raw)
    if len(placements) != 1:
        raise ValueError('missing unique Image allocation identity')
    image_start, _ = placements[0]
    if tuple(released['image_extent']) != placements[0]:
        raise ValueError('released Image extent does not match actual loader record')
    result = verify(re.sub(pattern, '', text, flags=re.MULTILINE), exit_status, mode, harts, 1)
    if result['image_start'] != image_start:
        raise ValueError('freed Image does not match the executed Image')
    result['manifest_fault'] = fault
    return result


if __name__ == '__main__':
    print(json.dumps(verify_manifest(Path(sys.argv[1]).read_text(errors='replace'),
                                    int(sys.argv[2]), sys.argv[3], int(sys.argv[4])),
                     sort_keys=True))
