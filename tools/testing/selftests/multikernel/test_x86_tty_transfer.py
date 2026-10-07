#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the real capture endpoints across a bounded transport boundary."""
import base64
import hashlib
import unittest
from unittest import mock

import x86_tty_child_init as child
import x86_tty_host_init as host

NONCE = '1234567890abcdef'
RECORDS = [b'6,0,1,-;' + b'x' * 50000 + b'\n',
           b'6,1,2,-;MKTTY_LOG_END_1234567890abcdef\n']


class CaptureTransfer(unittest.TestCase):
    def setUp(self):
        self.pending = []
        self.all_records = []
        self.enterContext(mock.patch.object(child, 'capture', None, create=True))
        self.enterContext(mock.patch.object(child, 'read_records', return_value=RECORDS))
        self.enterContext(mock.patch.object(child, 'marker', side_effect=self.emit))
        self.enterContext(mock.patch.object(child.Path, 'read_text', return_value='0'))
        self.enterContext(mock.patch.object(child, 'snapshot', return_value={'online_cpus': [3, 4, 5]}))

    def emit(self, name, **fields):
        self.pending.append((name, fields))
        self.all_records.append((name, fields))

    def test_health_starts_capture_without_bursting_log(self):
        child.command(NONCE, {'op': 'health'})
        self.assertEqual(len(self.pending), 1, 'capture flooded the unread host RX buffer')
        self.assertEqual(self.pending[0][0], 'TTY_KMSG_READY')
        self.assertGreater(self.pending[0][1]['chunks'], 1)

    def test_each_chunk_requires_a_correlated_request(self):
        child.command(NONCE, {'op': 'health'})
        self.pending.clear()
        for nonce, fields in ((NONCE, {'op': 'log-next', 'index': 1}),
                              ('fedcba0987654321', {'op': 'log-next', 'index': 0}),
                              (NONCE, {'op': 'log-next', 'index': False})):
            with self.assertRaises(RuntimeError):
                child.command(nonce, fields)
            self.assertEqual(self.pending, [])
        child.command(NONCE, {'op': 'log-next', 'index': 0})
        self.assertEqual([name for name, _ in self.pending], ['TTY_KMSG'])
        self.pending.clear()
        with self.assertRaises(RuntimeError):
            child.command(NONCE, {'op': 'log-next', 'index': 0})
        self.assertEqual(self.pending, [])

    def test_host_pulls_complete_snapshot_without_unread_chunk_accumulation(self):
        self.assertTrue(callable(getattr(host, 'capture_log', None)), 'bounded host capture driver missing')
        test = self

        class Transport:
            def send(self, op, **fields):
                test.assertEqual(test.pending, [], 'host requested data before consuming prior response')
                child.command(NONCE, dict(op=op, **fields))

            def wait(self, name, **expected):
                got_name, value = test.pending.pop(0)
                test.assertEqual(got_name, name)
                for key, expected_value in expected.items():
                    test.assertEqual(value[key], expected_value)
                return value

        host.capture_log(Transport())
        self.assertEqual(self.pending, [])
        chunks = [fields for name, fields in self.all_records if name == 'TTY_KMSG']
        self.assertEqual([v['index'] for v in chunks], list(range(len(chunks))))
        actual = b''.join(base64.b64decode(v['data'], validate=True) for v in chunks)
        expected = b''.join(len(v).to_bytes(4, 'big') + v for v in RECORDS)
        self.assertEqual(actual, expected)
        final = [v for name, v in self.all_records if name == 'TTY_KMSG_COMPLETE'][0]
        self.assertEqual(final['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(final['records'], 2)
        self.assertIsNone(child.capture)


if __name__ == '__main__':
    unittest.main()
