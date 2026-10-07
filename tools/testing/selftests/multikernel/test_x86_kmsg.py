#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal log-transfer regressions; these cannot qualify native execution."""
import base64
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import test_verify_x86_nested as nested_fixture
import test_verify_x86_tty as tty_fixture
import verify_x86_tty
import x86_kmsg

NONCE = '1234567890abcdef'
END = b'MKTTY_LOG_END_1234567890abcdef'


def log_records():
    return [b'6,0,1,-;Linux version fixture\n', b'14,1,2,-;' + END + b'\n']


def transfer(records=None):
    records = log_records() if records is None else records
    blob = b''.join(len(record).to_bytes(4, 'big') + record for record in records)
    return [mark('TTY_KMSG', index=0, data=base64.b64encode(blob).decode()),
            mark('TTY_KMSG_COMPLETE', chunks=1, bytes=len(blob), records=len(records),
                 sha256=hashlib.sha256(blob).hexdigest())]


def mark(name, **fields):
    return 'MK_X86_' + name + ' ' + json.dumps(dict(nonce=NONCE, **fields)) + '\n'


def trace(log=None):
    nested = nested_fixture.NestedPoolGate().trace()
    held, final = tty_fixture.TtyOracle().records()
    middle = [mark('TTY_BEGIN', taint=0), mark('TTY_HELD', state=held),
              mark('TTY_COMPLETE', state=final, taint=0)]
    middle += transfer() if log is None else log
    middle += [mark('TTY_CHILD_HEALTH', taint=0, online_cpus=[3, 4, 5],
                    boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb')]
    tail = [line.replace('nested-pool-prerequisite', 'native-tty') for line in nested[7:]]
    return ''.join(nested[:7] + middle + tail)


class KmsgReadback(unittest.TestCase):
    def test_end_marker_is_finalized_before_nonblocking_read(self):
        readable = [log_records()[0]]

        def write(fd, message):
            self.assertEqual(message, b'<6>MKTTY_LOG_END_1234567890abcdef\n')
            readable.append(log_records()[1])
            return len(message)

        def read(fd, count):
            if not readable:
                raise BlockingIOError(errno.EAGAIN, 'unfinalized end marker')
            return readable.pop(0)

        with mock.patch.object(x86_kmsg.os, 'open', return_value=50), \
                mock.patch.object(x86_kmsg.os, 'close'), \
                mock.patch.object(x86_kmsg.os, 'write', side_effect=write), \
                mock.patch.object(x86_kmsg.os, 'read', side_effect=read):
            self.assertEqual(x86_kmsg.read_records(NONCE), log_records())

    def test_short_end_marker_write_is_fatal(self):
        with mock.patch.object(x86_kmsg.os, 'open', return_value=50), \
                mock.patch.object(x86_kmsg.os, 'close'), \
                mock.patch.object(x86_kmsg.os, 'write', side_effect=lambda fd, data: len(data) - 1):
            with self.assertRaisesRegex(RuntimeError, 'short kernel-log end-marker write'):
                x86_kmsg.read_records(NONCE)

    def verify(self, value):
        return verify_x86_tty.verify(value, nested_fixture.REVISION)

    def test_complete_clean_readback(self):
        self.assertEqual(self.verify(trace()), [])

    def test_missing_log_or_encoded_diagnostic_rejected(self):
        self.assertTrue(self.verify(trace([])), 'missing retained child log accepted')
        for diagnostic in (b'WARNING: lockdep report', b'BUG: fault', b'Oops: fault',
                           b'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:',
                           b'Kernel panic - not syncing:', b'watchdog: BUG: soft lockup'):
            records = [b'6,0,1,-;' + diagnostic + b'\n', log_records()[1]]
            with self.subTest(diagnostic=diagnostic):
                self.assertTrue(self.verify(trace(transfer(records))))

    def test_missing_duplicate_truncated_and_uncorrelated_records_rejected(self):
        for records in (log_records()[1:], log_records() * 2,
                        [log_records()[0], b'14,2,2,-;' + END + b'\n'],
                        [log_records()[0], b'14,1,2,-;wrong end\n'],
                        [b'broken header', log_records()[1]]):
            with self.subTest(records=records):
                self.assertTrue(self.verify(trace(transfer(records))))
        for field, value in (('chunks', 2), ('bytes', 1), ('records', 3), ('sha256', '0' * 64),
                             ('nonce', 'fedcba0987654321')):
            lines = transfer()
            final = json.loads(lines[-1].split(' ', 1)[1])
            final[field] = value
            lines[-1] = 'MK_X86_TTY_KMSG_COMPLETE ' + json.dumps(final) + '\n'
            with self.subTest(field=field):
                self.assertTrue(self.verify(trace(lines)))

    def test_log_must_follow_reconnect_phase_before_health(self):
        lines = transfer()
        self.assertTrue(self.verify(''.join(lines) + trace([])))
        self.assertTrue(self.verify(trace([]) + ''.join(lines)))

    def test_reader_stops_at_marker_and_fails_on_overrun(self):
        path = Path(__file__).with_name('x86_kmsg.py')
        self.assertTrue(path.is_file(), 'retained kernel-log reader missing')
        spec = importlib.util.spec_from_file_location('x86_kmsg_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # read returns actual /dev/kmsg-shaped records; never mock the reader.
        for input_records in (log_records(), [OSError(errno.EPIPE, 'lost records')],
                              [BlockingIOError(errno.EAGAIN, 'end without marker')],
                              [log_records()[1]], [b'x' * 65536]):
            with mock.patch.object(module.os, 'open', return_value=50), \
                    mock.patch.object(module.os, 'close'), \
                    mock.patch.object(module.os, 'write', side_effect=lambda fd, data: len(data)), \
                    mock.patch.object(module.os, 'read', side_effect=input_records):
                if input_records == log_records():
                    self.assertEqual(module.read_records(NONCE), log_records())
                else:
                    with self.assertRaises((OSError, ValueError, RuntimeError)):
                        module.read_records(NONCE)


if __name__ == '__main__':
    unittest.main()
