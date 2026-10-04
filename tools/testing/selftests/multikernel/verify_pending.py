# SPDX-License-Identifier: GPL-2.0-only
"""Additional mode-6 fault evidence; normal verifier must also pass."""
import json
from pathlib import Path
import re
import sys
from verify_lifecycle import verify


def verify_pending(text, exit_status):
    result = verify(text, exit_status, 'graceful', 2, 1)
    records = [json.loads(match[1]) for match in
               re.finditer(r'^MK_LIFECYCLE_STOPPED ([^\n]*)$', text, re.MULTILINE)]
    stopped = records[0]
    for hart in stopped['harts']:
        if text.count(f'MK_FW_PENDING mode=6 hart={hart} actual=1 reported=3') != 1:
            raise ValueError('firmware did not inject the requested hart status')
        observations = [int(match[1]) for line in stopped['hsm_trace']
                        for match in re.finditer(r'\bhart=' + str(hart) + r' state=(\d+)\b', line)]
        if len(observations) < 2 or observations[0] != 3 or observations[-1] != 1:
            raise ValueError('bounded pending-to-stopped polling not observed')
    result['fault'] = 'synthetic STOP_PENDING then actual STOPPED'
    return result


if __name__ == '__main__':
    print(json.dumps(verify_pending(Path(sys.argv[1]).read_text(errors='replace'), int(sys.argv[2])),
                     sort_keys=True))
