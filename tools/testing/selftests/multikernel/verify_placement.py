# SPDX-License-Identifier: GPL-2.0-only
"""Private physical-placement rejection/retry proof, not hardware qualification."""
from collections import Counter
import json
from pathlib import Path
import re
import sys
from verify_lifecycle import verify
from verify_retention import loaded_extents, release_control, resources


def verify_placement(text, exit_status, harts):
    pattern = r'^MK_LIFECYCLE_(PLACEMENT_REJECTED|PLACEMENT_RECOVERED|PLACEMENT_RELEASED) ([^\n]*)\n?'
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if [match[1] for match in matches] != ['PLACEMENT_REJECTED', 'PLACEMENT_RECOVERED', 'PLACEMENT_RELEASED']:
        raise ValueError('missing, duplicate or unordered placement checks')
    rejected, recovered, released = [json.loads(match[2]) for match in matches]
    begin_match = re.search(r'^MK_LIFECYCLE_BEGIN ([^\n]*)$', text, re.MULTILINE)
    if not begin_match:
        raise ValueError('missing requested scope')
    begin = json.loads(begin_match[1])
    if (begin.get('fault') != 0 or begin.get('cycles') != 1 or begin.get('images') != 'same' or
            rejected.get('error') != 12 or rejected.get('state') != 'ready' or
            rejected.get('ownership_unchanged') is not True or
            not begin.get('host_boot') or rejected.get('host_boot') != begin['host_boot']):
        raise ValueError('wrong scope, errno, state, ownership or host identity')
    ready = text.find('MK_CHILD_READY ')
    child = text.find('MK_LIFECYCLE_CHILD ')
    stopped = text.find('MK_LIFECYCLE_STOPPED ')
    passed = text.find('MK_LIFECYCLE_PASS ')
    if not begin_match.end() < matches[0].start() < ready < child < matches[1].start() < stopped < matches[2].start() < passed:
        raise ValueError('rejection, recovery and stopped cleanup are not ordered')

    # Tracefs output is also emitted verbatim, separately from the JSON claims.
    blocks = list(re.finditer(r'^MK_PLACEMENT_TRACE_BEGIN (rejected|recovered)\n(.*?)'
                             r'^MK_PLACEMENT_TRACE_END \1$', text, re.MULTILINE | re.DOTALL))
    if ([block[1] for block in blocks] != ['rejected', 'recovered'] or
            text.count('MK_PLACEMENT_TRACE_BEGIN ') != 2 or text.count('MK_PLACEMENT_TRACE_END ') != 2):
        raise ValueError('missing or duplicate raw trace windows')
    if not begin_match.end() < blocks[0].start() < blocks[0].end() < matches[0].start() < child < blocks[1].start() < blocks[1].end() < matches[1].start():
        raise ValueError('raw traces outside their operation windows')
    for record, block in zip((rejected, recovered), blocks):
        trace = record.get('trace')
        if (not isinstance(trace, list) or not trace or
                not all(isinstance(line, str) for line in trace) or trace != block[2].splitlines()):
            raise ValueError('trace claim does not match actual raw trace')
    before, after = [block[2] for block in blocks]
    if 'mk_copy:' in before or 'mk_start:' in before:
        raise ValueError('rejected load copied or started a hart')
    boundaries = list(re.finditer(r': MK_PLACEMENT_EXEC$', after, re.MULTILINE))
    if len(boundaries) != 1:
        raise ValueError('missing or duplicate load-to-exec trace boundary')
    loading, after = after[:boundaries[0].start()], after[boundaries[0].end():]
    if 'mk_copy:' not in loading or 'mk_start:' in loading:
        raise ValueError('retry load must copy segments without starting harts')
    if 'mk_copy:' not in after or 'mk_start:' not in after or after.rfind('mk_copy:') >= after.find('mk_start:'):
        raise ValueError('recovery lacks ordered positive copy/start traces')
    for hart in begin.get('harts', []):
        states = re.findall(r'mk_hsm_status:.*\bhart=' + re.escape(str(hart)) + r' state=(-?\d+)\b',
                            after[:after.index('mk_copy:')])
        if not states or states[-1] != '1':
            raise ValueError('latest pre-copy observation is not STOPPED')

    raw = '\n'.join(line for line in text.splitlines() if not line.startswith('MK_LIFECYCLE_'))
    if 'MK_TEST_MANIFEST' in raw or 'MK_FW_REJECT' in raw or 'MK_FW_PENDING' in raw:
        raise ValueError('unexpected unrelated fault injection')
    guard = rejected.get('guard_log', '')
    injection = r'MK_TEST_PLACEMENT id=1 original=0x([0-9a-f]+) injected=0x([0-9a-f]+) size=(\d+) align=0x([0-9a-f]+)\b'
    injections = list(re.finditer(injection, raw))
    if (not isinstance(guard, str) or not guard.strip() or raw.count(guard.strip()) != 1 or
            raw.count('MK_TEST_PLACEMENT') != 1 or len(injections) != 1 or
            len(re.findall(injection, guard)) != 1):
        raise ValueError('missing actual one-shot placement injection')
    original, injected, size, align = [int(value, base) for value, base in
                                      zip(injections[0].groups(), (16, 16, 10, 16))]
    if (original <= 0 or align != 0x200000 or original % align or
            injected != (original | 4096) or injected - original != 4096 or size <= 0):
        raise ValueError('wrong original alignment or injected page offset')
    rejection = r'Multikernel allocation not aligned: phys=0x([0-9a-f]+), required=0x([0-9a-f]+)\b'
    rejected_addresses = list(re.finditer(rejection, guard))
    if (raw.count('Multikernel allocation not aligned:') != 1 or len(rejected_addresses) != 1 or
            tuple(int(value, 16) for value in rejected_addresses[0].groups()) != (injected, align)):
        raise ValueError('missing matching alignment rejection')
    free_pattern = r'MK_TEST_FREE id=1 kind=(\w+) phys=([0-9a-f]+) size=(\d+) pool=([0-9a-f]+)\b'
    failed_frees = list(re.finditer(free_pattern, guard))
    if len(failed_frees) != 1:
        raise ValueError('failed allocation must be freed exactly once')
    free = failed_frees[0]
    if (free[1] != 'allocation' or int(free[2], 16) != original or int(free[3]) != size or
            int(free[4], 16) <= 0 or not guard.index('MK_TEST_PLACEMENT') < rejected_addresses[0].start() < free.start()):
        raise ValueError('free does not match the original allocation after rejection')

    # Reuse the healthy manifest lane's release proof, without claiming its fault.
    release_control(released)
    release_log = released.get('release_log', '')
    all_frees = re.findall(free_pattern, raw)
    if (released['resources']['owned'] != harts or int(free[4], 16) != released['resources']['pool'] or
            not release_log.strip() or raw.count(release_log.strip()) != 1 or
            raw.count('MK_TEST_FREE id=1 ') != len(all_frees) or
            any(int(address, 16) == injected for address in re.findall(
                r'MK_TEST_FREE id=\d+ kind=\w+ phys=([0-9a-f]+)\b', raw)) or
            Counter(all_frees) != Counter(re.findall(free_pattern, guard + release_log))):
        raise ValueError('uncorrelated release outside rejection or stopped cleanup')
    placements = loaded_extents(raw)
    if len(placements) != 1 or tuple(released['image_extent']) != placements[0]:
        raise ValueError('released Image does not match actual retry placement')
    if not raw.index(guard.strip()) + len(guard.strip()) < raw.index('kexec_file(Image): Loaded kernel at ') < raw.index(release_log.strip()):
        raise ValueError('original allocation was not freed before retry')
    snapshots = resources(raw, 'loaded')
    if not snapshots or snapshots[-1] != released['resources']:
        raise ValueError('release identity does not match actual loaded resources')
    result = verify(re.sub(pattern, '', text, flags=re.MULTILINE), exit_status,
                    'placement-negative', harts, 1)
    if result['image_start'] != placements[0][0]:
        raise ValueError('freed Image does not match executed Image')
    return result


if __name__ == '__main__':
    print(json.dumps(verify_placement(Path(sys.argv[1]).read_text(errors='replace'),
                                     int(sys.argv[2]), int(sys.argv[3])), sort_keys=True))
