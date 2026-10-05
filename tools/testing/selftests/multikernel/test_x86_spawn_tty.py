#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal observer records; not a substitute for native execution."""
import copy
import importlib.util
from pathlib import Path
import socket
import hashlib
import json
import unittest
import verify_x86_tty as verifier
import test_verify_x86_nested as nested_fixture
import test_x86_kmsg as kmsg_fixture


def records(mode):
    session = mode in ('spawn-close', 'spawn-hangup')
    number = {'spawn-close': 1, 'spawn-hangup': 2, 'spawn-overflow': 3, 'spawn-offline': 4}[mode]
    points = [1, 2, 3, 4, 5, 9, 6, 7, 8] if session else [1, 2, 5, 9, 6]
    if number == 2:
        points = [1, 2, 10, 3, 4, 5, 9, 6, 7, 11, 8]
    events = [dict(seq=i, point=p, cpu=2 if number == 4 and p in (1, 2) else 1,
                   hardirq=False, vector=False) for i, p in enumerate(points, 1)]
    held = dict(mode=number, cookie='1234567890abcdef', work='ffff0100', failed=False,
                released=False, worker_done=False, drained=False, reopened=False,
                drain_waiting=session, input=20000 if number == 3 else 32,
                copied=16384 if number == 3 else 32, dropped=3616 if number == 3 else 0,
                peak=16384 if number == 3 else 32, dequeued=32 if session else 0,
                discarded=0, inserted=0, rx_irq=True, events=events[:5 if number == 2 else 4 if session else 2])
    final = dict(held, released=True, worker_done=True, drained=session, reopened=session,
                 drain_waiting=False, dequeued=16384 if number == 3 else 32,
                 inserted=16384 if number == 3 else 32, events=events)
    return held, final


class SpawnOracle(unittest.TestCase):
    def test_exact_receive_rejects_stale_bytes_and_truncation(self):
        path = Path(__file__).with_name('x86_spawn_tty.py')
        self.assertTrue(path.exists(), 'spawn session driver missing')
        spec = importlib.util.spec_from_file_location('x86_spawn_tty', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for payload, good in ((b'fresh', True), (b'oldfresh', False), (b'fre', False)):
            left, right = socket.socketpair()
            with left, right:
                left.setblocking(False)
                right.sendall(payload)
                right.shutdown(socket.SHUT_WR)
                if good:
                    self.assertEqual(module.read_exact(left.fileno(), b'fresh'), b'fresh')
                else:
                    with self.assertRaises(RuntimeError):
                        module.read_exact(left.fileno(), b'fresh')

    def check(self, mode, held, final):
        function = getattr(verifier, 'verify_spawn_records', None)
        self.assertTrue(callable(function), 'spawn-session native evidence oracle missing')
        return function(mode, held, final)

    def test_good_literal_records(self):
        for mode in ('spawn-close', 'spawn-hangup', 'spawn-overflow', 'spawn-offline'):
            self.assertEqual(self.check(mode, *records(mode)), [])

    def test_missing_wait_late_insert_drain_or_reopen_rejected(self):
        for mode in ('spawn-close', 'spawn-hangup'):
            for point in (2, 3, 4, 5, 9, 6, 7, 8):
                held, final = records(mode)
                final['events'] = [e for e in final['events'] if e['point'] != point]
                self.assertTrue(self.check(mode, held, final))
            held, final = records(mode)
            held['drain_waiting'] = False
            self.assertTrue(self.check(mode, held, final))
            held, final = records(mode)
            final['events'][5], final['events'][7] = final['events'][7], final['events'][5]
            self.assertTrue(self.check(mode, held, final))

    def test_overflow_exact_accounting_and_context(self):
        for field, value in (('copied', 20000), ('dropped', 0), ('peak', 20000),
                             ('input', True), ('rx_irq', False), ('failed', True)):
            held, final = records('spawn-overflow')
            held[field] = value
            self.assertTrue(self.check('spawn-overflow', held, final))
        held, final = records('spawn-overflow')
        final['dequeued'] = 16383
        self.assertTrue(self.check('spawn-overflow', held, final))

    def test_offline_requires_same_worker_continuation_elsewhere(self):
        held, final = records('spawn-offline')
        final['events'][3]['cpu'] = 2
        self.assertTrue(self.check('spawn-offline', held, final))
        held, final = records('spawn-offline')
        held['events'][0]['cpu'] = 0
        self.assertTrue(self.check('spawn-offline', held, final))
        held, final = records('spawn-offline')
        final['work'] = 'ffff0200'
        self.assertTrue(self.check('spawn-offline', held, final))

    def test_bool_counter_duplicate_and_irq_worker_rejected(self):
        for mode in ('spawn-close', 'spawn-overflow', 'spawn-offline'):
            held, final = copy.deepcopy(records(mode))
            final['events'][-1]['hardirq'] = True
            self.assertTrue(self.check(mode, held, final))
            held, final = copy.deepcopy(records(mode))
            final['events'][0]['seq'] = True
            self.assertTrue(self.check(mode, held, final))
            held, final = copy.deepcopy(records(mode))
            final['events'].append(final['events'][-1])
            self.assertTrue(self.check(mode, held, final))

    def test_actual_late_insertion_and_hangup_path_required(self):
        for mode in ('spawn-close', 'spawn-hangup'):
            held, final = records(mode)
            final['inserted'] = 0
            self.assertTrue(self.check(mode, held, final))
        for point in (10, 11):
            held, final = records('spawn-hangup')
            final['events'] = [e for e in final['events'] if e['point'] != point]
            self.assertTrue(self.check('spawn-hangup', held, final))

    def test_complete_trace_requires_fresh_bytes_and_overlapping_offline(self):
        nonce = '1234567890abcdef'
        def mark(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(dict(nonce=nonce, **fields)) + '\n'
        for mode in ('spawn-close', 'spawn-hangup', 'spawn-overflow', 'spawn-offline'):
            nested = nested_fixture.NestedPoolGate().trace()
            held, final = records(mode)
            fields = dict(fresh='MKTTY_FRESH_' + nonce, stale=False) if mode in ('spawn-close', 'spawn-hangup') else dict(received=16384 if mode == 'spawn-overflow' else 32, sha256=hashlib.sha256(b'X' * (16384 if mode == 'spawn-overflow' else 32)).hexdigest())
            extra = dict(offline=[0, 1]) if mode == 'spawn-offline' else {}
            if extra:
                fields.update(offline=[0, 1], restored=[0, 1, 2])
            def trace():
                middle = [mark('TTY_BEGIN', mode=mode, taint=0), mark('TTY_HELD', state=held, **extra), mark('TTY_COMPLETE', state=final, taint=0, **fields)]
                middle += kmsg_fixture.transfer()
                middle += [mark('TTY_CHILD_HEALTH', taint=0, online_cpus=[3, 4, 5], boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb')]
                return ''.join(nested[:7] + middle + [s.replace('nested-pool-prerequisite', 'native-tty') for s in nested[7:]])
            self.assertEqual(verifier.verify(trace(), nested_fixture.REVISION, mode), [])
            if mode == 'spawn-offline':
                fields['offline'] = [0, 1, 2]
            elif mode == 'spawn-overflow':
                fields['received'] = 20000
            else:
                fields['fresh'] = 'old'
            self.assertTrue(verifier.verify(trace(), nested_fixture.REVISION, mode))


if __name__ == '__main__':
    unittest.main()
