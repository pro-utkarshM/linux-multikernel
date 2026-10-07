#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject snapshot success without actual contention and bounded retry."""
import copy
import errno
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

NONCE = '1234567890abcdef'


def records(removal=False):
    enter = dict(seq=9, point=9, request=5, cpu=0, result=1, operation=0)
    leave = dict(seq=10, point=10, request=5, cpu=0, result=0, operation=0)
    held = dict(nonce=NONCE, gate=dict(active=True, point=1, overflow=False, events=[enter]),
                reads={name: dict(errno=11, elapsed_ms=1) for name in ('root', 'instance')})
    done = dict(nonce=NONCE, removal=removal, transaction=5, status='applied',
                gate=dict(active=False, point=0, overflow=False, events=[enter, leave]),
                root=dict(cpus=[3, 4, 5, 6, 7], available=[3, 4, 5, 6, 7] if removal else [5, 6, 7]),
                instance=None if removal else dict(cpus=[3, 4]),
                stale_errno=19 if removal else 0,
                retries={name: dict(attempts=2, elapsed_ms=1) for name in ('root', 'instance')})
    return held, done


def trace(removal=False):
    held, done = records(removal)
    def mark(name, fields):
        return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
    return (mark('NESTED_BEGIN', dict(child_cpus=[3, 4, 5], spare_cpus=[6, 7])) +
            mark('PING', dict(nonce=NONCE)) +
            mark('NESTED_UNLOADED' if removal else 'NESTED_POOL_RETIRED', {}) +
            mark('SNAPSHOT_HELD', held) + mark('SNAPSHOT_SETTLED', done) +
            mark('DESTROY_HELD' if removal else 'ADMISSION_BEGIN', {}))


class SnapshotOracle(unittest.TestCase):
    def verifier(self):
        path = Path(__file__).with_name('verify_x86_snapshot.py')
        self.assertTrue(path.exists(), 'snapshot verifier not implemented')
        spec = importlib.util.spec_from_file_location('verify_x86_snapshot', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_update_and_removal_accept_only_expected_resources(self):
        for removal in (False, True):
            self.assertEqual(self.verifier().verify(trace(removal), removal=removal), [])

    def test_missing_gate_busy_proof_or_bounded_retry_fails(self):
        for path, value in ((('gate', 'active'), False), (('gate', 'overflow'), True),
                            (('gate', 'point'), 2), (('gate', 'events'), []),
                            (('reads', 'root', 'errno'), 0),
                            (('reads', 'instance', 'elapsed_ms'), 30000)):
            held, done = records()
            item = held
            for key in path[:-1]:
                item = item[key]
            item[path[-1]] = value
            self.assertTrue(self.verifier().verify_records(held, done, [3, 4, 5], [6, 7], False))

    def test_wrong_resources_transaction_timeout_and_stale_fd_success_fail(self):
        for removal in (False, True):
            held, done = records(removal)
            for key, value in (('transaction', 6), ('status', 'failed'), ('root', {}),
                               ('instance', {'cpus': [3, 4, 5]}),
                               ('retries', {'root': {'attempts': 1, 'elapsed_ms': 1}})):
                bad = dict(done, **{key: value})
                self.assertTrue(self.verifier().verify_records(held, bad, [3, 4, 5], [6, 7], removal))
            bad = copy.deepcopy(done)
            bad['gate']['events'][-1]['point'] = 11
            self.assertTrue(self.verifier().verify_records(held, bad, [3, 4, 5], [6, 7], removal))
        held, done = records(True)
        done['stale_errno'] = 0
        self.assertTrue(self.verifier().verify_records(held, done, [3, 4, 5], [6, 7], True))

    def test_missing_reordered_or_uncorrelated_phase_fails(self):
        text = trace()
        lines = text.splitlines(keepends=True)
        for bad in (text.replace('MK_X86_SNAPSHOT_HELD', 'MISSING'),
                    text.replace('"nonce": "' + NONCE + '"', '"nonce": "bad"', 1),
                    ''.join(lines[:3] + [lines[4], lines[3]] + lines[5:]),
                    ''.join(lines[:3] + lines[5:] + lines[3:5])):
            self.assertTrue(self.verifier().verify(bad))


class SnapshotRetry(unittest.TestCase):
    def helper(self):
        path = Path(__file__).with_name('x86_snapshot.py')
        self.assertTrue(path.exists(), 'bounded snapshot retry not implemented')
        spec = importlib.util.spec_from_file_location('x86_snapshot', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_retry_accepts_data_or_deactivated_descriptor_but_not_arbitrary_errors(self):
        module = self.helper()
        for end in (b'new snapshot', OSError(errno.ENODEV, 'removed')):
            with patch.object(module.os, 'pread', side_effect=[BlockingIOError(errno.EAGAIN, 'busy'), end]), \
                    patch.object(module.time, 'sleep'):
                value = module.retry(123)
            self.assertEqual(value['attempts'], 3)  # includes the earlier held-lock EAGAIN
            self.assertEqual(value['data'], end if isinstance(end, bytes) else None)
            self.assertEqual(value['errno'], 0 if isinstance(end, bytes) else errno.ENODEV)
        with patch.object(module.os, 'pread', side_effect=OSError(errno.EIO, 'bad')):
            with self.assertRaises(OSError):
                module.retry(123)

    def test_persistent_eagain_is_bounded(self):
        module = self.helper()
        with patch.object(module.os, 'pread', side_effect=BlockingIOError(errno.EAGAIN, 'busy')), \
                patch.object(module.time, 'sleep'):
            with self.assertRaises(TimeoutError):
                module.retry(123)


if __name__ == '__main__':
    unittest.main()
