# SPDX-License-Identifier: GPL-2.0-only
import json
import unittest
from test_verify_lifecycle import event
from verify_fault import verify_fault
from test_verify_pending import pending_log


def denied_log():
    return ('OpenSBI v1.8.1\nMK_FW_REJECT mode=4 hart=65537 entry=0x88000000 error=-4\n' +
            event('BEGIN', mode='deny-primary', fault=4, harts=[65537, 7], cycles=1,
                  host_boot='host', images='same') +
            event('REJECTED', error=1, harts=[65537, 7], host_alive=True, cleanup='ready',
                  hsm_trace=['mk_hsm_status: hart=65537 state=1', 'mk_hsm_status: hart=7 state=1']) +
            event('PASS', mode='deny-primary', cycles=1, host_alive=True))


class Fault(unittest.TestCase):
    def test_partial_start_requires_secondary_denial(self):
        text = pending_log().replace('graceful', 'partial-start').replace('"images": "same"', '"images": "same", "fault": 5')
        text += 'MK_FW_REJECT mode=5 hart=7 entry=0x88000000 error=-4\n'
        self.assertEqual(verify_fault(text, 0, 'partial-start', 5)['result'], 'PASS')
        with self.assertRaises(ValueError):
            verify_fault(text.replace('mode=5 hart=7', 'mode=0 hart=7'), 0, 'partial-start', 5)

    def test_permanent_pending_retains_resources_and_rejects_reuse(self):
        text = pending_log().replace('graceful', 'stuck-stop').replace('"images": "same"', '"images": "same", "fault": 7')
        rows = text.splitlines(keepends=True)
        rows = [row for row in rows if not row.startswith(('MK_LIFECYCLE_STOPPED', 'MK_LIFECYCLE_PASS', 'MK_FW_PENDING'))]
        text = (''.join(rows) + event('RETAINED', harts=[65537, 7], host_alive=True,
                                     state='failed', no_copy_or_start=True, ownership_unchanged=True,
                                     rejected=dict.fromkeys(('exec', 'unload', 'destroy'), 16)) +
                event('PASS', mode='stuck-stop', cycles=1, host_alive=True, retained_until_vm_shutdown=True) +
                'MK_FW_PENDING mode=7 hart=65537 actual=1 reported=3\n' +
                'MK_FW_PENDING mode=7 hart=7 actual=1 reported=3\n')
        self.assertEqual(verify_fault(text, 0, 'stuck-stop', 7)['result'], 'PASS')
        for before, after in (('"exec": 16', '"exec": 0'),
                              ('"ownership_unchanged": true', '"ownership_unchanged": false'),
                              ('mode=7 hart=7', 'mode=0 hart=7')):
            with self.assertRaises(ValueError):
                verify_fault(text.replace(before, after), 0, 'stuck-stop', 7)

    def test_primary_denial_and_cleanup_proved(self):
        self.assertEqual(verify_fault(denied_log(), 0, 'deny-primary', 4)['result'], 'PASS')

    def test_wrong_fault_errno_stop_or_child_execution_rejected(self):
        for before, after in (('mode=4', 'mode=0'), ('"error": 1', '"error": 22'),
                              ('hart=7 state=1', 'hart=7 state=3'),
                              ('"cleanup": "ready"', '"cleanup": "failed"')):
            with self.assertRaises(ValueError):
                verify_fault(denied_log().replace(before, after), 0, 'deny-primary', 4)
        with self.assertRaises(ValueError):
            verify_fault(denied_log() + 'MK_CHILD_READY\n', 0, 'deny-primary', 4)


if __name__ == '__main__':
    unittest.main()
