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


def resources(text, state=None, require_ctrl=True):
    result=[]
    for line in text.splitlines():
        if 'MK_TEST_RESOURCE id=1 ' not in line:
            continue
        values=dict(re.findall(r'(\w+)=([\w-]+)', line))
        if state is not None and values.get('state') != state:
            continue
        try:
            row={key: int(values[key], 16 if key in FIELDS[:5] else 10)
                 for key in (*FIELDS, 'tracked')}
        except (KeyError, ValueError) as error:
            raise ValueError('malformed resource snapshot') from error
        if any(row[key] <= 0 for key in FIELDS if key!='ctrl' or require_ctrl):
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


def verify_retention(text, exit_status, mode, fault):
    if exit_status or (mode, fault) not in (('failed-retain',8), ('lost-ack',0), ('lost-ack',7)):
        raise ValueError('failed process or unsupported injected scope')
    if re.search(r'MK_LIFECYCLE_FAIL|MK_CHILD_FAIL|WARNING:|BUG:|Oops:|KASAN:|UBSAN:|'
                 r'Kernel panic|Call Trace:|soft lockup|hung task',text):
        raise ValueError('unexpected guest diagnostic')
    if not re.search(r'^OpenSBI v',text,re.MULTILINE):
        raise ValueError('missing firmware identity')
    raw='\n'.join(line for line in text.splitlines() if not line.startswith('MK_LIFECYCLE_'))
    expected_markers={'failed-retain':{'REJECT','PENDING'},'lost-ack':{'PENDING'} if fault==7 else set()}[mode]
    for kind,selector,hart in re.findall(r'MK_FW_(REJECT|PENDING) mode=(\d+) hart=(\d+)',raw):
        if kind not in expected_markers or int(selector)!=fault:
            raise ValueError('contradictory firmware injection evidence')
    records=[(m[1],json.loads(m[2])) for m in re.finditer(r'^MK_LIFECYCLE_(\w+) ([^\n]*)$',text,re.MULTILINE)]
    expected=(['BEGIN','CONTROL','REJECTED','RETAINED','PASS'] if mode=='failed-retain' else
              ['BEGIN','CONTROL','CHILD','TIMEOUT','RETAINED','PASS'] if fault==7 else
              ['BEGIN','CONTROL','CHILD','TIMEOUT','RECOVERED','STOPPED','PASS'])
    if [kind for kind,_ in records]!=expected:
        raise ValueError('missing, duplicate or out-of-order scenario')
    data=dict(records)
    begin, final=data['BEGIN'],data['PASS']
    harts=begin.get('harts',[])
    if any(int(hart) not in harts for _,_,hart in re.findall(r'MK_FW_(REJECT|PENDING) mode=(\d+) hart=(\d+)',raw)):
        raise ValueError('firmware injection targets unowned hart')
    if (len(harts)!=2 or len(set(harts))!=2 or begin.get('mode')!=mode or
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
        child, timeout=data['CHILD'],data['TIMEOUT']
        if (child.get('assigned')!=harts or child.get('ring_roundtrip') is not True or
            child.get('active_unload_rejected') is not True or len(child.get('online',[]))!=2 or
            not child.get('boot') or child['boot']==begin.get('host_boot') or
            not re.fullmatch(r'[0-9a-f]{64}',child.get('image_sha','')) or
            text.count('MK_CHILD_READY ')!=(2 if fault==0 else 1) or
            text.count('MK_CHILD_PONG')!=(2 if fault==0 else 1)):
            raise ValueError('shutdown request lacks actual child/transport control')
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
    if mode=='failed-retain' or fault==7:
        raw='\n'.join(line for line in text.splitlines() if not line.startswith('MK_LIFECYCLE_'))
        pattern=r'MK_TEST_FREE id=1 kind=\w+ phys=[0-9a-f]+ size=\d+ pool=[0-9a-f]+'
        if Counter(re.findall(pattern,raw))!=Counter(re.findall(pattern,data['CONTROL']['release_log'])):
            raise ValueError('actual release outside the healthy control')
        retained=data['RETAINED']
        state='failed' if mode=='failed-retain' else 'active'
        before,after=retained.get('resources_before',{}),retained.get('resources_after',{})
        snapshots=resources(retained.get('guard_log',''),state)
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
            if name=='exec' and not any(re.search(r'hart='+str(hart)+r' state=3\b',trace) for hart in harts):
                raise ValueError('exec refusal did not exercise HSM pending')
        tx=retained.get('destroy_tx','')
        if not re.fullmatch(r'tx_\d+',tx) or not re.search(r'Failed to apply overlay transaction '+tx[3:]+r': -16\b',text):
            raise ValueError('uncorrelated removal failure')
        if not any(f'MK_FW_PENDING mode={fault} hart={hart} actual=1 reported=3' in text for hart in harts):
            raise ValueError('pending injection absent')
    else:
        recovered,stopped=data['RECOVERED'],data['STOPPED']
        trace='\n'.join(recovered.get('trace',[]))
        first_copy=trace.find('mk_copy:')
        if first_copy<0 or 'mk_start:' not in trace[first_copy:]:
            raise ValueError('recovery did not execute actual recopy/start')
        for hart in harts:
            states=re.findall(r'hart='+str(hart)+r' state=(-?\d+)\b',trace[:first_copy])
            if not states or states[-1]!='1' or not any(
                re.search(r'hart='+str(hart)+r' state=1\b',line) for line in stopped.get('hsm_trace',[])):
                raise ValueError('reuse or cleanup without all-hart stop proof')
        if (recovered.get('host_alive') is not True or recovered.get('boot')==data['CHILD']['boot'] or
            not recovered.get('boot') or stopped.get('harts')!=harts or stopped.get('host_alive') is not True):
            raise ValueError('recovery not a fresh contained child')
    return {'result':'PASS','mode':mode,'fault':fault,'harts':harts}


if __name__=='__main__':
    print(json.dumps(verify_retention(Path(sys.argv[1]).read_text(errors='replace'),int(sys.argv[2]),
                                     sys.argv[3],int(sys.argv[4])),sort_keys=True))
