#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal MKTTY lifetime evidence; never a native execution substitute."""
import copy
import importlib.util
from pathlib import Path
import unittest


class TtyOracle(unittest.TestCase):
    def verify(self, held, final):
        path = Path(__file__).with_name('verify_x86_tty.py')
        self.assertTrue(path.is_file(), 'native MKTTY verifier missing')
        spec = importlib.util.spec_from_file_location('verify_x86_tty', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_records(held, final)

    def records(self):
        def event(point):
            irq = point in (1, 4, 9)
            return dict(seq=point, point=point, cpu=0 if irq else 2 if point == 3 else 1,
                        hardirq=irq, vector=irq)
        held = dict(cookie='1234567890abcdef', connection='ffff0010', buffer='ffff0020',
                    released=False, failed=False, closed=False, unmatched=0,
                    events=[event(1), event(2)])
        final = dict(held, released=True, closed=True, unmatched=1,
                     events=[event(i) for i in range(1, 10)])
        return held, final

    def test_good_literal_lifetime(self):
        self.assertEqual(self.verify(*self.records()), [])

    def worker_records(self):
        held, final = self.records()
        points = (1, 4, 10, 6, 11, 12, 3, 13, 14, 7, 8, 9)
        events = []
        for seq, point in enumerate(points, 1):
            irq = point in (1, 4, 9)
            cpu = 0 if irq or point in (10, 13) else 2 if point == 3 else 1
            events.append(dict(seq=seq, point=point, cpu=cpu, hardirq=irq, vector=irq))
        held.update(mode='worker', flush_waiting=True, events=events[:6])
        final.update(mode='worker', flush_waiting=False, events=events)
        return held, final

    def test_worker_drain_literal(self):
        self.assertEqual(self.verify(*self.worker_records()), [])

    def test_worker_drain_rejects_start_marker_and_early_free(self):
        held, final = self.worker_records()
        held['flush_waiting'] = False
        self.assertTrue(self.verify(held, final))
        for point in (10, 11, 12, 13, 14):
            held, final = self.worker_records()
            final['events'] = [e for e in final['events'] if e['point'] != point]
            self.assertTrue(self.verify(held, final))
        held, final = self.worker_records()
        final['events'][7]['hardirq'] = True
        self.assertTrue(self.verify(held, final))
        held, final = self.worker_records()
        final['events'][8]['point'], final['events'][9]['point'] = 7, 14
        self.assertTrue(self.verify(held, final))

    def test_missing_or_early_free_and_wrong_cpu_rejected(self):
        for index in range(9):
            held, final = self.records()
            final['events'].pop(index)
            self.assertTrue(self.verify(held, final))
        for field, value in (('closed', True), ('released', True), ('failed', True),
                             ('connection', '0'), ('buffer', '0')):
            held, final = self.records()
            held[field] = value
            self.assertTrue(self.verify(held, final))
        held, final = copy.deepcopy(self.records())
        final['events'][0]['vector'] = False
        self.assertTrue(self.verify(held, final))
        held, final = self.records()
        final['events'][3]['point'], final['events'][7]['point'] = 8, 4
        self.assertTrue(self.verify(held, final))


if __name__ == '__main__':
    unittest.main()
