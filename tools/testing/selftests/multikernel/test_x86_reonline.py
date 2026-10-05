#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The diagnostic must not turn missing/error/uncorrelated evidence into success."""
import unittest

import x86_reonline


class ReonlineVerdictTest(unittest.TestCase):
    def record(self, phase, **extra):
        return dict(nonce='0123456789abcdef', phase=phase, cpu=1,
                    physical_cpu=3, **extra)

    def test_complete_roundtrip_and_scheduler_progress(self):
        records = [self.record('before', online='0-1'),
                   self.record('offline', online='0'),
                   self.record('online', online='0-1', ran_on=1)]
        self.assertEqual(x86_reonline.classify(records, '0123456789abcdef'), 'restored')
        for changed in ([records[0], records[-1]],
                        records + [records[-1]],
                        [records[0], records[1], dict(records[2], ran_on=0)],
                        [records[0], dict(records[1], online='0-1'), records[2]],
                        [dict(records[0], nonce='other'), *records[1:]],
                        [records[0], records[1], dict(records[2], cpu=True)]):
            with self.subTest(records=changed), self.assertRaises(ValueError):
                x86_reonline.classify(changed, '0123456789abcdef')

    def test_failure_requires_offline_and_explicit_errno(self):
        records = [self.record('before', online='0-1'),
                   self.record('offline', online='0'),
                   self.record('error', online='0', errno=5)]
        self.assertEqual(x86_reonline.classify(records, '0123456789abcdef'), 'online-error')
        for changed in (records[:2], records[1:],
                        [*records[:2], dict(records[2], errno=True)],
                        [*records[:2], dict(records[2], online='0-1')]):
            with self.subTest(records=changed), self.assertRaises(ValueError):
                x86_reonline.classify(changed, '0123456789abcdef')


if __name__ == '__main__':
    unittest.main()
