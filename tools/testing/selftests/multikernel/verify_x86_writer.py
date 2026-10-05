#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify actual ring publication excludes Image unload, not ring-page free."""
import argparse
import json
from pathlib import Path
import re
from verify_x86_nested import verify as verify_nested, validate_nested_bundle


def verify_records(held, final):
    try:
        for key in ('cookie', 'instance', 'image', 'ring'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('writer correlation/identity mismatch')
        if (held['instance'] == held['image'] or type(held.get('segments')) is not int
                or held['segments'] <= 0 or final.get('segments') != held['segments']):
            raise ValueError('actual loaded Image segments missing')
        for state, done in ((held, False), (final, True)):
            if (any(state.get(key) is not done for key in ('released', 'sent', 'probed'))
                    or state.get('failed') is not False or type(state.get('send_result')) is not int
                    or state['send_result'] != 0 or type(state.get('probe_result')) is not int
                    or state['probe_result'] != (-19 if done else 0)):
                raise ValueError('unproven writer hold, publication or closed-ring rejection')
        events = final['events']
        if len(events) != 6 or held['events'] != events[:2]:
            raise ValueError('missing or inconsistent writer events')
        for index, event in enumerate(events, 1):
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != index or event['point'] != index
                    or event['cpu'] != {1: 0, 2: 1, 3: 2, 4: 0, 5: 1, 6: 1}[index]
                    or event.get('hardirq') is not False
                    or event.get('irqs_off') is not (index in (1, 4, 5))):
                raise ValueError('early deactivation/free, wrong CPU or IRQ context')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []


def verify(trace, revision):
    errors = verify_nested(trace, revision, qualification='native-writer')
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': expected exactly one event')
            return matches[0].start(), json.loads(matches[0][1])
        begin_at, begin = one('WRITER_BEGIN')
        held_at, held = one('WRITER_HELD')
        final_at, final = one('WRITER_COMPLETE')
        nonce = one('PING')[1]['nonce']
        if not one('NESTED_HALTED')[0] < begin_at < held_at < final_at < one('NESTED_UNLOADED')[0]:
            raise ValueError('writer test must follow confirmed stop and precede unloaded observation')
        if any(v.get('nonce') != nonce for v in (begin, held, final)):
            raise ValueError('writer nonce mismatch')
        if (any(v.get('taint') != 0 for v in (begin, final))
                or any(v['state']['cookie'] != nonce for v in (held, final))):
            raise ValueError('writer taint/correlation failure')
        errors += verify_records(held['state'], final['state'])
    except (KeyError, ValueError, TypeError) as error:
        errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    errors = validate_nested_bundle(args.bundle, args.revision, profile='writer')
    errors += verify(args.trace.read_text(errors='replace'), args.revision)
    for error in errors:
        print('FAIL:', error)
    if not errors:
        print('PASS: native producer/Image unload; persistent ring-page destruction not qualified')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
