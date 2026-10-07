# SPDX-License-Identifier: GPL-2.0-only
import json
import unittest
from test_verify_lifecycle import complete_log
from verify_pending import verify_pending


def pending_log():
    text = complete_log()
    rows = text.splitlines(keepends=True)
    for index, row in enumerate(rows):
        if row.startswith('MK_LIFECYCLE_'):
            kind, _, value = row.partition(' ')
            value = json.loads(value)
            if 'harts' in value:
                value['harts'] = [65537, 7]
            if 'assigned' in value:
                value['assigned'] = [65537, 7]
            if 'hsm_trace' in value:
                value['hsm_trace'] = [f'mk_hsm_status: hart={hart} state={state}'
                                      for hart in [65537, 7] for state in [0, 2] + [3] * 32 + [1]]
            rows[index] = kind + ' ' + json.dumps(value) + '\n'
    return ''.join(rows) + ''.join(f'MK_FW_PENDING mode=6 hart={hart} actual=1 reported=3\n'
                                 for hart in [65537, 7])


class Pending(unittest.TestCase):
    def test_natural_pending_before_synthetic_pending_is_allowed(self):
        text = pending_log().replace('mk_hsm_status: hart=7 state=3',
                                     'mk_hsm_status: hart=7 state=3", "mk_hsm_status: hart=7 state=3', 1)
        self.assertEqual(verify_pending(text, 0)['result'], 'PASS')

    def test_each_assigned_hart_injected_and_resolves(self):
        self.assertEqual(verify_pending(pending_log(), 0)['result'], 'PASS')

    def test_wrong_selector_or_no_transition_is_not_a_pass(self):
        for before, after in (('mode=6', 'mode=0'), ('hart=7 state=3', 'hart=7 state=1'),
                              ('hart=7 state=1', 'hart=7 state=3')):
            with self.assertRaises(ValueError):
                verify_pending(pending_log().replace(before, after), 0)
        with self.assertRaises(ValueError):
            verify_pending(pending_log().replace('mk_hsm_status: hart=7 state=3', '', 1), 0)


if __name__ == '__main__':
    unittest.main()
