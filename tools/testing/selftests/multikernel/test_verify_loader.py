# SPDX-License-Identifier: GPL-2.0-only
import json
import unittest
from test_verify_lifecycle import complete_log, event
from verify_loader import verify_loader


def loader_log():
    rows = complete_log().replace('graceful', 'loader-negative').splitlines(keepends=True)
    rows[4] += event('LOADER_RECOVERED', tracer_exercised=True)
    rejected = ''.join(event('LOAD_REJECTED', case=case, error=error, state='ready',
                             no_copy_or_start=True, ownership_unchanged=True)
                       for case, error in (('bad-magic', 22), ('bad-text-offset', 22),
                                           ('image-too-large', 12), ('initrd-too-large', 12)))
    return ''.join(rows[:2]) + rejected + ''.join(rows[2:])


class LoaderVerification(unittest.TestCase):
    def test_rejections_are_followed_by_real_valid_execution_and_cleanup(self):
        self.assertEqual(verify_loader(loader_log(), 0, 1)['result'], 'PASS')

    def test_missing_wrong_untraced_or_late_failure_evidence_is_rejected(self):
        text = loader_log()
        for before, after in (('"error": 12', '"error": 22'),
                              ('"state": "ready"', '"state": "loaded"'),
                              ('"ownership_unchanged": true', '"ownership_unchanged": false'),
                              ('"tracer_exercised": true', '"tracer_exercised": false'),
                              ('initrd-too-large', 'image-too-large')):
            with self.assertRaises(ValueError):
                verify_loader(text.replace(before, after), 0, 1)
        rejection = next(row for row in text.splitlines(keepends=True)
                         if row.startswith('MK_LIFECYCLE_LOAD_REJECTED'))
        with self.assertRaises(ValueError):
            verify_loader(text.replace(rejection, '') + rejection, 0, 1)


if __name__ == '__main__':
    unittest.main()
