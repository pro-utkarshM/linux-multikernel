# SPDX-License-Identifier: GPL-2.0-only
"""Private native retention lane; no synthetic claim of executing-hart safety."""
import json
from collections import Counter
from pathlib import Path
import re
import sys

FIELDS = ('image', 'ctrl', 'manifest', 'ring', 'pool', 'size', 'owned', 'ring_size', 'manifest_size')


def loaded_extents(text):
    return [(int(address, 16), int(size, 16)) for address, size in re.findall(
        r'kexec_file\(Image\): Loaded kernel at (0x[0-9a-f]+) '
        r'bufsz=0x[0-9a-f]+ memsz=(0x[0-9a-f]+)', text)]


def resources(text, state=None, require_ctrl=True, strict=False):
    result=[]
    for line in text.splitlines():
        if 'MK_TEST_RESOURCE id=1 ' not in line:
            continue
        values=dict(re.findall(r'(\w+)=([\w-]+)', line))
        if state is not None and values.get('state') != state:
            if strict:
                raise ValueError('resource state changed during retention')
            continue
        try:
            row={key: int(values[key], 16 if key in FIELDS[:5] else 10)
                 for key in (*FIELDS, 'tracked')}
        except (KeyError, ValueError) as error:
            raise ValueError('malformed resource snapshot') from error
        if any(row[key] <= 0 for key in FIELDS if key!='ctrl' or require_ctrl):
            if strict:
                raise ValueError('resource cleared during retention')
            continue  # Early READY/retired records have no published Image.
        result.append(row)
    return result


def release_control(record):
    before=record.get('resources', {})
    log=record.get('release_log', '')
    extent=record.get('image_extent')
    if (not isinstance(extent, (list, tuple)) or len(extent)!=2 or
        any(type(value) is not int or value<=0 for value in extent)):
        raise ValueError('missing Image allocation extent')
    if (any(not isinstance(before.get(key), int) or before[key] <= 0 for key in FIELDS if key!='ctrl') or
        not isinstance(before.get('ctrl'),int) or before['ctrl']<0):
        raise ValueError('missing control allocation identity')
    rows=[dict(re.findall(r'(\w+)=([\w-]+)', line)) for line in log.splitlines()
          if 'MK_TEST_FREE id=1 ' in line]
    identities=[(row.get('kind'),row.get('phys'),row.get('pool')) for row in rows]
    if len(set(identities))!=len(identities) or any(row.get('kind') not in
            ('allocation','ring','manifest','pool') for row in rows):
        raise ValueError('duplicate or unknown release identity')
    required=[('ring',before['ring'],before['ring_size']),
              ('manifest',before['manifest'],before['manifest_size']),('pool',0,before['size']),
              ('allocation',extent[0],extent[1])]
    if before['ctrl']:
        required.append(('allocation',before['ctrl'],None))
    for kind,address,size in required:
        matches=[row for row in rows if row.get('kind')==kind and int(row.get('phys','-1'),16)==address and
                 (size is None or int(row.get('size','-1'))==size) and
                 (kind in ('ring','manifest') or int(row.get('pool','-1'),16)==before['pool'])]
        if len(matches)!=1 or (kind!='allocation' and sum(row.get('kind')==kind for row in rows)!=1):
            raise ValueError('release instrumentation not positively exercised')
    if any(row.get('kind')=='allocation' and (int(row.get('pool','-1'),16)!=before['pool'] or
            int(row.get('size','-1'))<=0 or int(row.get('phys','-1'),16)<=0) for row in rows):
        raise ValueError('uncorrelated allocation release')
    if extent[0]==before['ctrl']:
        raise ValueError('control allocation cannot substitute for the Image')


def hsm_samples(log, harts):
    """Decode complete sequential observation groups, never authorize reuse."""
    groups = []
    pattern = (r'MK_TEST_HSM id=1 phase=exec-rejected sample=([1-9][0-9]*) '
               r'hart=(\d+) state=(-?\d+) error=(-?\d+)$')
    for line in log.splitlines():
        if 'MK_TEST_HSM' not in line:
            continue
        match = re.search(pattern, line)
        if not match:
            raise ValueError('malformed or wrong-scope HSM observation')
        sample, hart, state, error = map(int, match.groups())
        if error or state not in range(7) or hart not in harts:
            raise ValueError('uncertain or unowned HSM observation')
        if not groups or groups[-1]['sample'] != sample:
            if groups and sample <= groups[-1]['sample']:
                raise ValueError('reordered HSM group')
            groups.append({'sample': sample, 'states': {}})
        states = groups[-1]['states']
        if hart in states:
            raise ValueError('duplicate hart in HSM group')
        states[hart] = state
    if any(set(group['states']) != set(harts) for group in groups):
        raise ValueError('incomplete all-hart observation')
    return groups


def retention_window(raw, mode, host_boot):
    markers = []
    for kind in ('BEGIN', 'END'):
        token = f'MK_TEST_RETAIN_{kind} id=1 mode={mode} host_boot={host_boot}'
        matches = list(re.finditer(r'^.*' + re.escape(token) + r'\r?$', raw, re.M))
        if raw.count('MK_TEST_RETAIN_' + kind) != 1 or len(matches) != 1:
            raise ValueError('missing or duplicate retention boundary')
        markers.append(matches[0])
    if markers[0].end() >= markers[1].start():
        raise ValueError('reordered retention boundaries')
    outside = raw[:markers[0].start()] + raw[markers[1].end():]
    if 'MK_TEST_HSM' in outside:
        raise ValueError('stale or unbound HSM observation')
    return raw[markers[0].end():markers[1].start()].strip()


def trace_block(raw, phase):
    start = f'MK_RETENTION_TRACE_BEGIN {phase}\n'
    end = f'MK_RETENTION_TRACE_END {phase}'
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('missing or duplicate raw trace control')
    first, last = raw.index(start) + len(start), raw.index(end)
    if first >= last:
        raise ValueError('empty or reordered raw trace')
    return raw[first:last].strip()


def retention_trace(trace, health, mode, host_boot):
    """Require a bounded, non-overwritten trace with its probes still enabled."""
    if health.get('enabled') != dict(tracing_on='1', mk_copy='1', mk_start='1'):
        raise ValueError('retention tracing/probes disabled')
    stats = health.get('stats', {})
    if set(stats) != {'cpu0', 'cpu1', 'cpu2', 'cpu3'}:  # Fixed four-hart virt recipe.
        raise ValueError('missing per-CPU trace loss accounting')
    for cpu in stats.values():
        for field in ('overrun', 'commit overrun', 'dropped events'):
            if re.findall(r'^' + field + r': (\d+)$', cpu, re.M) != ['0']:
                raise ValueError('lost or unaccounted trace events')
    counts = re.findall(r'^# entries-in-buffer/entries-written: (\d+)/(\d+)\s', trace, re.M)
    if len(counts) != 1 or counts[0][0] != counts[0][1]:
        raise ValueError('trace buffer overwritten or missing header')
    positions = []
    for kind in ('BEGIN', 'END'):
        token = f'MK_RETENTION_GUARD_{kind} id=1 mode={mode} host_boot={host_boot}'
        matches = list(re.finditer(r'tracing_mark_write: ' + re.escape(token) + '$', trace, re.M))
        if len(matches) != 1:
            raise ValueError('missing or duplicate trace boundary')
        positions.append(matches[0].start())
    if positions[0] >= positions[1] or re.search(r'mk_copy:|mk_start:', trace):
        raise ValueError('reordered trace boundary or forbidden copy/start')


def verify_retention(text, exit_status, mode, fault):
    if exit_status or (mode, fault) not in (('failed-retain',8), ('lost-ack',0),
                                          ('lost-ack',7), ('panic-retain',0), ('contended-retain',0)):
        raise ValueError('failed process or unsupported injected scope')
    if re.search(r'MK_LIFECYCLE_FAIL|MK_CHILD_FAIL|MK_TEST_SHUTDOWN_FAIL|WARNING:|BUG:|Oops:|KASAN:|UBSAN:|'
                 r'soft lockup|hung task',text):
        raise ValueError('unexpected guest diagnostic')
    if not re.search(r'^OpenSBI v',text,re.MULTILINE):
        raise ValueError('missing firmware identity')
    raw='\n'.join(line for line in text.splitlines() if not line.startswith('MK_LIFECYCLE_'))
    expected_markers = {'REJECT', 'PENDING'} if mode == 'failed-retain' else {'PENDING'} if fault == 7 else set()
    for kind,selector,hart in re.findall(r'MK_FW_(REJECT|PENDING) mode=(\d+) hart=(\d+)',raw):
        if kind not in expected_markers or int(selector)!=fault:
            raise ValueError('contradictory firmware injection evidence')
    matches = list(re.finditer(r'^MK_LIFECYCLE_(\w+) ([^\n]*)$',text,re.MULTILINE))
    records=[(m[1],json.loads(m[2])) for m in matches]
    expected=(['BEGIN','CONTROL','REJECTED','RETAINED','PASS'] if mode=='failed-retain' else
              ['BEGIN','CONTROL','CHILD', {'panic-retain': 'PANIC', 'contended-retain': 'CONTENDED'}.get(mode, 'TIMEOUT'),
               'RETAINED','PASS'])
    if [kind for kind,_ in records]!=expected:
        raise ValueError('missing, duplicate or out-of-order scenario')
    data=dict(records)
    begin, final=data['BEGIN'],data['PASS']
    harts=begin.get('harts',[])
    if mode == 'panic-retain':
        first, last = matches[2].end(), matches[3].start()
        interval = text[first:last]
        required = ('MK_CHILD_ACTION mode=panic', 'Trigger a crash',
                    'Kernel panic - not syncing: sysrq triggered crash', 'Rebooting in 1 seconds')
        positions = [interval.find(item) for item in required]
        if (any(text.count(item) != 1 for item in required) or
                positions[0] < 0 or positions != sorted(set(positions)) or
                data['PANIC'] != {'state': 'active', 'host_boot': begin.get('host_boot'), 'timeout': 1}):
            raise ValueError('missing ordered intentional panic/timeout')
        for diagnostic in re.finditer(r'Kernel panic|Call Trace:|Trigger a crash|Rebooting in \d+ seconds', text):
            if not first <= diagnostic.start() < last:
                raise ValueError('panic diagnostic outside child action')
        if text.count('Kernel panic') != 1 or 'MK_TEST_ACK_DROPPED' in raw:
            raise ValueError('unexpected extra panic or ACK injection')
    elif re.search(r'Kernel panic|Call Trace:|Trigger a crash|Rebooting in \d+ seconds', text):
        raise ValueError('unexpected panic')
    if mode == 'contended-retain':
        interval = text[matches[2].end():matches[3].start()]
        action = 'MK_CHILD_ACTION mode=poweroff'
        proof = 'MK_TEST_SHUTDOWN_CONTENDED id=1 held=1 trylock=0 released=1'
        if (text.count(action) != 1 or text.count('MK_TEST_SHUTDOWN_CONTENDED') != 1 or
                interval.find(action) < 0 or interval.find(proof) <= interval.find(action) or
                not re.search(re.escape(proof) + r'\r?$', interval, re.M) or
                data['CONTENDED'] != {'state': 'active', 'host_boot': begin.get('host_boot'), 'action': 'poweroff'} or
                'MK_TEST_ACK_DROPPED' in text):
            raise ValueError('unproven or wrong-scope voluntary shutdown contention')
    elif 'MK_TEST_SHUTDOWN_CONTENDED' in text:
        raise ValueError('unexpected contention injection')
    if any(int(hart) not in harts for _,_,hart in re.findall(r'MK_FW_(REJECT|PENDING) mode=(\d+) hart=(\d+)',raw)):
        raise ValueError('firmware injection targets unowned hart')
    if (len(harts)!=2 or any(type(hart) is not int or hart < 0 for hart in harts) or
        len(set(harts))!=2 or not begin.get('host_boot') or begin.get('mode')!=mode or
        begin.get('fault')!=fault or begin.get('cycles')!=1 or begin.get('images')!='same' or
        final.get('mode')!=mode or final.get('cycles')!=1 or final.get('host_alive') is not True):
        raise ValueError('scope or survival not established')
    allocations=loaded_extents(raw)
    if not allocations or tuple(data['CONTROL'].get('image_extent', []))!=allocations[0]:
        raise ValueError('control Image extent does not match actual loader record')
    release_control(data['CONTROL'])
    if mode=='failed-retain':
        rejected=data['REJECTED']
        if (rejected.get('error')!=1 or rejected.get('state')!='failed' or
            rejected.get('tracer_exercised') is not True or 'MK_CHILD_READY' in text or
            not re.search(r'MK_FW_REJECT mode=8 hart=(?:'+ '|'.join(map(str,harts))+r') entry=0x[0-9a-f]+ error=-4\b',text)):
            raise ValueError('FAILED not reached through actual denied primary')
    else:
        child=data['CHILD']
        ready = list(re.finditer(r'^MK_CHILD_READY [^\n]* boot=(\S+) release=(\S+)\r?$', raw, re.M))
        if (child.get('assigned')!=harts or child.get('ring_roundtrip') is not True or
            child.get('active_unload_rejected') is not True or len(child.get('online',[]))!=2 or
            not child.get('boot') or child['boot']==begin.get('host_boot') or
            not re.fullmatch(r'[0-9a-f]{64}',child.get('image_sha','')) or
            len(ready)!=1 or ready[0].groups()!=(child.get('boot'),child.get('release')) or
            len(re.findall(r'^MK_CHILD_PONG\r?$', raw, re.M))!=1):
            raise ValueError('shutdown request lacks actual child/transport control')
    if mode == 'lost-ack':
        timeout=data['TIMEOUT']
        ack=timeout.get('ack',{})
        raw='\n'.join(line for line in text.splitlines() if not line.startswith('MK_LIFECYCLE_'))
        drops=re.findall(r'MK_TEST_ACK_DROPPED type=(\d+) operation=(\d+) resource=(\d+) request=(\d+) result=(-?\d+)',raw)
        wanted=(12288,12290,1,ack.get('request'),0)
        if (timeout.get('error')!=110 or timeout.get('state')!='active' or
            not 29<=timeout.get('elapsed',0)<=65 or not isinstance(wanted[3],int) or wanted[3]<=0 or
            ack!={'type':12288,'operation':12290,'resource':1,'request':wanted[3],'result':0} or
            len(drops)!=1 or tuple(map(int,drops[0]))!=wanted or
            'Timeout waiting for operation 0x3002 on resource 1' not in raw):
            raise ValueError('matching successful ACK loss/real timeout absent')
    # All supported modes retain; automatic ACTIVE recovery is not accepted.
    pattern=r'MK_TEST_FREE id=1 kind=\w+ phys=[0-9a-f]+ size=\d+ pool=[0-9a-f]+'
    if Counter(re.findall(pattern,raw))!=Counter(re.findall(pattern,data['CONTROL']['release_log'])):
        raise ValueError('actual release outside the healthy control')
    retained=data['RETAINED']
    state='failed' if mode=='failed-retain' else 'active'
    before,after=retained.get('resources_before',{}),retained.get('resources_after',{})
    snapshots=resources(retained.get('guard_log',''),state,strict=True)
    positive='\n'.join(retained.get('positive_trace',[]))
    if (retained.get('state')!=state or retained.get('harts')!=harts or
        any(retained.get(key) is not True for key in ('host_alive','no_copy_or_start','ownership_unchanged','tracer_exercised')) or
        any(before.get(key)!=after.get(key) or not isinstance(before.get(key),int) or before[key]<=0 for key in FIELDS) or
        before.get('owned')!=2 or after.get('tracked')!=2 or len(snapshots)<2 or
        'mk_copy:' not in positive or 'mk_start:' not in positive or
        any(any(row[key]!=before[key] for key in FIELDS) for row in snapshots) or
        'MK_TEST_FREE id=1 ' in retained.get('guard_log','') or
        final.get('retained_until_vm_shutdown') is not True):
        raise ValueError('missing actual retained allocation/ownership evidence')
    checks=retained.get('checks',{})
    if set(checks)!= {'exec','unload','destroy'}:
        raise ValueError('missing rejection boundary')
    for name,row in checks.items():
        trace='\n'.join(row.get('trace',[]))
        if row.get('error')!=('failed' if name=='destroy' else 16) or 'mk_copy:' in trace or 'mk_start:' in trace:
            raise ValueError('rejected operation copied/started or wrong error')
        if mode=='failed-retain' and name=='exec' and not any(re.search(r'hart='+str(hart)+r' state=3\b',trace) for hart in harts):
            raise ValueError('exec refusal did not exercise HSM pending')
    tx=retained.get('destroy_tx','')
    if not re.fullmatch(r'tx_\d+',tx) or not re.search(r'Failed to apply overlay transaction '+tx[3:]+r': -16\b',text):
        raise ValueError('uncorrelated removal failure')
    if fault and not any(f'MK_FW_PENDING mode={fault} hart={hart} actual=1 reported=3' in raw for hart in harts):
        raise ValueError('pending injection absent')
    if mode != 'failed-retain':
        window = retention_window(raw, mode, begin['host_boot'])
        groups = hsm_samples(window, harts)
        expected_state = 3 if fault == 7 else 1
        guard_trace = '\n'.join(retained.get('guard_trace', [])).strip()
        retention_trace(guard_trace, retained.get('trace_health', {}), mode, begin['host_boot'])
        for phase, first, last in (('positive', matches[2].end(), matches[3].start()),
                                   ('guarded', matches[3].end(), matches[4].start())):
            trace_block(raw, phase)
            if not first < text.index(f'MK_RETENTION_TRACE_BEGIN {phase}\n') < \
                    text.index(f'MK_RETENTION_TRACE_END {phase}') < last:
                raise ValueError('raw trace outside its action interval')
        if (window != retained.get('guard_log', '').strip() or len(groups) < 2 or
                any(state != expected_state for state in groups[-1]['states'].values()) or
                retained.get('observed_state') != ('stop-pending' if fault == 7 else 'stopped') or
                retained.get('host_boot') != begin['host_boot'] or final.get('host_boot') != begin['host_boot'] or
                any(row['tracked'] != 2 for row in snapshots) or
                trace_block(raw, 'positive') != positive.strip() or
                trace_block(raw, 'guarded') != guard_trace or
                re.search(r'mk_copy:|mk_start:', guard_trace)):
            raise ValueError('missing fresh complete retained observation/trace window')
    return {'result':'PASS','mode':mode,'fault':fault,'harts':harts}


if __name__=='__main__':
    print(json.dumps(verify_retention(Path(sys.argv[1]).read_text(errors='replace'),int(sys.argv[2]),
                                     sys.argv[3],int(sys.argv[4])),sort_keys=True))
