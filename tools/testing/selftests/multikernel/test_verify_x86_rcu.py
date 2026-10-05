#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal verifier fixtures; these never substitute for native RCU."""
import copy
import importlib.util
from pathlib import Path
import unittest


class NativeRcuOracle(unittest.TestCase):
    def test_completion_waits_for_last_observation_publication(self):
        import x86_rcu_host_init as host
        self.assertTrue(hasattr(host, 'complete'), 'completion predicate missing')
        _, final = self.records()
        self.assertTrue(host.complete(final))
        final['events'].pop()
        self.assertFalse(host.complete(final))

    def verify(self, held, final):
        path = Path(__file__).with_name('verify_x86_rcu.py')
        self.assertTrue(path.is_file(), 'native RCU oracle missing')
        spec = importlib.util.spec_from_file_location('verify_x86_rcu', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_records(held, final)

    def records(self):
        def event(seq, point, cpu, hard=False, vector=False):
            return dict(seq=seq, point=point, cpu=cpu, hardirq=hard, vector=vector)
        events = [event(1, 1, 0, True, True), event(2, 2, 1), event(3, 3, 1)]
        held = dict(cookie='1234567890abcdef', handler='ffff0001', context='ffff0002',
                    invocations=1, consumed=0, released=False, timed_out=False,
                    waiter_sleeping=True, done=False, overflow=False, events=events)
        final = dict(held, released=True, done=True, waiter_sleeping=False, consumed=2,
                     events=events + [event(4, 9, 2), event(5, 4, 0, True, True),
                                      event(6, 8, 0, True, True), event(7, 5, 1),
                                      event(8, 6, 1), event(9, 7, 1),
                                      event(10, 8, 0, True, True)])
        return held, final

    def test_literal_native_order(self):
        self.assertEqual(self.verify(*self.records()), [])

    def test_missing_boundaries(self):
        for index in range(10):
            held, final = self.records()
            final['events'].pop(index)
            self.assertTrue(self.verify(held, final))

    def test_false_grace_period_and_contexts(self):
        mutations = [('waiter_sleeping', False), ('invocations', 0), ('released', True),
                     ('timed_out', True), ('overflow', True), ('done', True),
                     ('handler', '0'), ('context', '0')]
        for key, value in mutations:
            held, final = self.records()
            held[key] = value
            self.assertTrue(self.verify(held, final), (key, value))
        for key, value in (('hardirq', False), ('vector', False), ('cpu', 2)):
            held, final = copy.deepcopy(self.records())
            final['events'][0][key] = value
            self.assertTrue(self.verify(held, final), (key, value))
        for key, value in (('invocations', 2), ('consumed', 1), ('cookie', 'bad'),
                           ('released', False), ('done', False)):
            held, final = self.records()
            final[key] = value
            self.assertTrue(self.verify(held, final), (key, value))


if __name__ == '__main__':
    unittest.main()
