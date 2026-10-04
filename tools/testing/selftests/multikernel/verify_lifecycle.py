# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed verifier for the modern QEMU lifecycle integration lane."""
import json
from pathlib import Path
import re
import sys


def verify(text, exit_status, mode, harts, cycles, images='same'):
    if exit_status or mode not in ('graceful', 'halt', 'poweroff', 'reboot', 'panic', 'partial-start', 'loader-negative', 'writer-stress'):
        raise ValueError('failed process or unsupported mode')
    if harts not in (1, 2) or not 1 <= cycles <= 50:
        raise ValueError('unsupported topology or cycle count')
    if images not in ('same', 'alternate') or (images == 'alternate' and cycles < 2):
        raise ValueError('unsupported Image replacement scope')
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
    phases = ['CHILD', 'STRESS', 'STOPPED'] if mode == 'writer-stress' else ['CHILD', 'STOPPED']
    if mode == 'writer-stress' and (cycles != 1 or images != 'same'):
        raise ValueError('writer stress requires one same-Image cycle')
    if [name for name, _ in records] != ['BEGIN'] + phases * cycles + ['PASS']:
        raise ValueError('missing, duplicate or out-of-order scenario')
    begin, final = records[0][1], records[-1][1]
    if (begin.get('mode') != mode or begin.get('cycles') != cycles or
            begin.get('images') != images or
            len(begin.get('harts', [])) != harts or len(set(begin['harts'])) != harts or
            final.get('mode') != mode or final.get('cycles') != cycles or
            final.get('host_alive') is not True):
        raise ValueError('wrong requested scope or host survival')
    if text.count('MK_CHILD_READY ') != cycles or len(re.findall(r'^MK_CHILD_PONG\r?$', text, re.M)) != cycles:
        raise ValueError('actual child execution/roundtrip missing')
    boots = set()
    loaded_images = []
    image_start = None
    panic_windows = []
    for cycle in range(1, cycles + 1):
        index = 1 + len(phases) * (cycle - 1)
        child, stopped = records[index][1], records[index + len(phases) - 1][1]
        if mode == 'writer-stress':
            stress = records[index + 1][1]
            if (stress.get('cycle') != cycle or
                    any(stress.get(field) != 64 for field in
                        ('unload_rejections', 'console_roundtrips', 'console_closes', 'closing_sends')) or
                    stress.get('incoming_workers_exercised') is not False or
                    stress.get('force_stop_error') != 95):
                raise ValueError('incomplete or overstated native writer scope')
            windows = stress.get('worker_windows')
            if (not isinstance(windows, list) or len(windows) != 2 or
                    any(not isinstance(window, list) or len(window) != 2 or
                        any(type(value) is not int for value in window) or
                        not 0 < window[0] < window[1] for window in windows) or
                    max(window[0] for window in windows) >= min(window[1] for window in windows)):
                raise ValueError('native worker intervals did not overlap')
            tokens = re.findall(r'^MK_CHILD_PONG token=round-(\d+)\r?$', text, re.M)
            if tokens != [str(value) for value in range(64)]:
                raise ValueError('missing, duplicated or reordered live console roundtrip')
        if (child.get('cycle') != cycle or stopped.get('cycle') != cycle or
                child.get('assigned') != begin['harts'] or stopped.get('harts') != begin['harts'] or
                child.get('ring_roundtrip') is not True or child.get('active_unload_rejected') is not True or
                stopped.get('host_alive') is not True or
                not child.get('boot') or child['boot'] in boots or
                child['boot'] == begin.get('host_boot')):
            raise ValueError('incomplete ownership, stop or new-child evidence')
        if not re.fullmatch(r'[0-9a-f]{64}', child.get('image_sha', '')):
            raise ValueError('missing loaded Image hash')
        start_address = child.get('image_start')
        if (not isinstance(start_address, int) or start_address <= 0 or
                start_address % (2 * 1024 * 1024)):
            raise ValueError('invalid Image placement')
        if image_start is not None and start_address != image_start:
            raise ValueError('Image physical address changed during replacement')
        image_start = start_address
        loaded_images.append((child['image_sha'], child.get('release')))
        evidence = stopped.get('hsm_trace', [])
        if not isinstance(evidence, list) or not all(isinstance(line, str) for line in evidence):
            raise ValueError('malformed raw HSM evidence')
        for hart in begin['harts']:
            if not any(re.search(r'mk_hsm_status:.*\bhart=' + str(hart) + r' state=1\b', line)
                       for line in evidence):
                raise ValueError('no raw STOPPED observation for assigned hart')
        start, end = matches[index].end(), matches[index + len(phases) - 1].start()
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
    if images == 'same' and len(set(loaded_images)) != 1:
        raise ValueError('same-Image test changed payload')
    if images == 'alternate':
        if (len(set(loaded_images)) != 2 or len({sha for sha, _ in loaded_images}) != 2 or
                len({release for _, release in loaded_images}) != 2 or
                any(value != loaded_images[index % 2] for index, value in enumerate(loaded_images))):
            raise ValueError('distinct executing Images did not alternate')
    return {'result': 'PASS', 'firmware': firmware.group(0), 'mode': mode,
            'harts': harts, 'cycles': cycles, 'images': images, 'image_start': image_start}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]).read_text(errors='replace'),
                            int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
                            int(sys.argv[5]), sys.argv[6] if len(sys.argv) > 6 else 'same'), sort_keys=True))
