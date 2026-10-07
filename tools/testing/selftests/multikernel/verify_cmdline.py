# SPDX-License-Identifier: GPL-2.0-only
"""Match the command-line allocation epoch to real allocator events."""
import json
from pathlib import Path
import re
import sys
from verify_lifecycle import verify


def verify_record(row):
    phase = row.get('phase')
    control = phase == 'control'
    if (phase not in ('rejected', 'control') or row.get('error') != (0 if control else 22)
            or row.get('state') != 'ready' or row.get('ownership_unchanged') is not True
            or not isinstance(row.get('command'), str)
            or row.get('length') != len(row['command'].encode()) + int(control)):
        raise ValueError('wrong command-line validation scope or cleanup state')
    table = row.get('kimage', '')
    if not table.startswith('MK_ID') or re.search(r'^\s*\d+\s+', table, re.M):
        raise ValueError('failed/unloaded Image still published or missing proc evidence')
    if control and (row.get('loaded_state') != 'loaded' or not re.search(
            r'^\s*1\s+multikernel\s+0x[0-9a-f]+\s+[1-9][0-9]*\s+file\s+"'
            + re.escape(row['command']) + r'"$', row.get('loaded_kimage', ''), re.M)):
        raise ValueError('successful Image did not retain its command line')
    health = row.get('health', {})
    if (health.get('enabled') != dict(tracing_on='0', alloc='1', kmalloc='1', kfree='1')
            or health.get('filters') != {key: 'common_pid == 1' for key in ('alloc', 'kmalloc', 'kfree')}
            or set(health.get('stats', {})) != {f'cpu{i}' for i in range(4)}):
        raise ValueError('missing active probes, PID filter or per-CPU loss accounting')
    profile = re.findall(r'^\s*mk_cmdline_alloc\s+(\d+)\s+(\d+)\s*$', health.get('profile', ''), re.M)
    if len(profile) != 1 or int(profile[0][0]) < 1 or profile[0][1] != '0':
        raise ValueError('return probe not exercised or missed a return')
    for stats in health['stats'].values():
        for field in ('overrun', 'commit overrun', 'dropped events'):
            if re.findall(r'^' + field + r': (\d+)$', stats, re.M) != ['0']:
                raise ValueError('lost or unaccounted allocator events')
    trace = row.get('trace', '')
    counts = re.findall(r'^# entries-in-buffer/entries-written: (\d+)/(\d+)\s', trace, re.M)
    if len(counts) != 1 or counts[0][0] != counts[0][1]:
        raise ValueError('trace buffer overwritten or missing header')
    def boundary(kind):
        token = f'MK_CMDLINE_{kind} {phase} {row.get("host_boot")}'
        positions = [m.start() for m in re.finditer(r'tracing_mark_write: ' + re.escape(token) + r'$', trace, re.M)]
        if len(positions) != 1:
            raise ValueError('missing or duplicate correlated trace boundary')
        return positions[0]
    begin, end = boundary('BEGIN'), boundary('END')
    if begin >= end:
        raise ValueError('reordered command-line window')
    returned = list(re.finditer(r'\bmk_cmdline_alloc:.*?\bptr=(0x[0-9a-f]+) length=(\d+)\b', trace))
    if len(returned) != 1:
        raise ValueError('missing or ambiguous command-line allocation')
    allocation = returned[0]
    pointer = int(allocation[1], 16)
    if (not (1 << 63) <= pointer < (1 << 64) - 4095
            or int(allocation[2]) != row['length'] or not begin < allocation.start() < end):
        raise ValueError('invalid command-line allocation pointer/length/order')
    events = [(m.start(), m[1], m[3]) for m in re.finditer(
        r'\b(kmalloc|kfree):[^\n]*?\bptr=(?:0x)?([0-9a-f]+)\b([^\n]*)', trace)
              if int(m[2], 16) == pointer and begin < m.start() < end]
    before = [event for event in events if event[0] < allocation.start()]
    if (not before or before[-1][1] != 'kmalloc'
            or re.findall(r'\bbytes_req=(\d+)\b', before[-1][2]) != [str(row['length'])]):
        raise ValueError('memdup return not backed by matching allocator allocation')
    after = [event for event in events if event[0] > allocation.start()]
    # Only this allocation epoch belongs to the command line. Address reuse
    # after its free is a different object, not evidence of a double free.
    if not after or after[0][1] != 'kfree':
        raise ValueError('command line leaked or overwritten before its free')
    if len(after) > 1 and after[1][1] != 'kmalloc':
        raise ValueError('duplicate free in the command-line allocation epoch')
    if control and not allocation.start() < boundary('LOADED') < boundary('UNLOAD') < after[0][0]:
        raise ValueError('command line freed before successful unload')
    return pointer


def verify_cmdline(text, exit_status, harts):
    pattern = r'^MK_LIFECYCLE_CMDLINE ([^\n]*)\n?'
    matches = list(re.finditer(pattern, text, re.M))
    rows = [json.loads(match[1]) for match in matches]
    if [row.get('phase') for row in rows] != ['rejected', 'control']:
        raise ValueError('missing or duplicated failed-load/control observations')
    begin = re.search(r'^MK_LIFECYCLE_BEGIN ([^\n]*)$', text, re.M)
    child = text.find('MK_LIFECYCLE_CHILD ')
    if not begin or not begin.end() < matches[0].start() < matches[1].start() < child:
        raise ValueError('command-line checks outside pre-spawn recovery interval')
    boot = json.loads(begin[1])['host_boot']
    for row in rows:
        if row.get('host_boot') != boot:
            raise ValueError('stale allocator observation')
        verify_record(row)
    return verify(re.sub(pattern, '', text, flags=re.M), exit_status, 'cmdline-cleanup', harts, 1)


if __name__ == '__main__':
    print(json.dumps(verify_cmdline(Path(sys.argv[1]).read_text(errors='replace'),
                                    int(sys.argv[2]), int(sys.argv[3])), sort_keys=True))
