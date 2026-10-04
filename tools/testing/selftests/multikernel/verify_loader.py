# SPDX-License-Identifier: GPL-2.0-only
"""Four actual file-load failures, then ordinary lifecycle recovery proof."""
import json
from pathlib import Path
import re
import sys
from verify_lifecycle import verify


def verify_loader(text, exit_status, harts):
    pattern = r'^MK_LIFECYCLE_(LOAD_REJECTED|LOADER_RECOVERED) ([^\n]*)\n?'
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    records = [(match[1], json.loads(match[2])) for match in matches]
    expected = [('bad-magic', 22), ('bad-text-offset', 22),
                ('image-too-large', 12), ('initrd-too-large', 12)]
    if [kind for kind, _ in records] != ['LOAD_REJECTED'] * 4 + ['LOADER_RECOVERED']:
        raise ValueError('missing or duplicate load rejection/recovery')
    begin = text.find('MK_LIFECYCLE_BEGIN ')
    child = text.find('MK_LIFECYCLE_CHILD ')
    stopped = text.find('MK_LIFECYCLE_STOPPED ')
    for match, (_, rejection), (case, error) in zip(matches[:4], records[:4], expected):
        if (not begin < match.start() < child or rejection.get('case') != case or
                rejection.get('error') != error or rejection.get('state') != 'ready' or
                rejection.get('no_copy_or_start') is not True or
                rejection.get('ownership_unchanged') is not True):
            raise ValueError('wrong failure cause, ordering or retained ownership')
    if (not child < matches[4].start() < stopped or
            records[4][1].get('tracer_exercised') is not True):
        raise ValueError('no positively exercised copy/start tracer during recovery')
    result = verify(re.sub(pattern, '', text, flags=re.MULTILINE), exit_status,
                    'loader-negative', harts, 1)
    result['load_rejections'] = [case for case, _ in expected]
    return result


if __name__ == '__main__':
    print(json.dumps(verify_loader(Path(sys.argv[1]).read_text(errors='replace'),
                                   int(sys.argv[2]), int(sys.argv[3])), sort_keys=True))
