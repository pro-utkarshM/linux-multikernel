#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal writer evidence rejects early Image reclamation; not native proof."""
import copy
import importlib.util
from pathlib import Path
import unittest


class WriterOracle(unittest.TestCase):
    def verify(self, held, final):
        path = Path(__file__).with_name('verify_x86_writer.py')
        self.assertTrue(path.is_file(), 'native writer verifier missing')
        spec = importlib.util.spec_from_file_location('verify_x86_writer', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_records(held, final)

    def records(self):
        def event(point):
            return dict(seq=point, point=point, cpu={1: 0, 2: 1, 3: 2, 4: 0, 5: 1, 6: 1}[point],
                        hardirq=False, irqs_off=point in (1, 4, 5))
        held = dict(cookie='1234567890abcdef', instance='ffff0010', image='ffff0020',
                    ring='800000', segments=5, released=False, failed=False,
                    sent=False, send_result=0, probed=False, probe_result=0,
                    events=[event(1), event(2)])
        final = dict(held, released=True, sent=True, probed=True, probe_result=-19,
                     events=[event(i) for i in range(1, 7)])
        return held, final

    def test_valid_literal_unload(self):
        self.assertEqual(self.verify(*self.records()), [])

    def test_every_native_boundary_and_identity_required(self):
        for index in range(6):
            held, final = self.records()
            final['events'].pop(index)
            self.assertTrue(self.verify(held, final))
        for key, value in (('instance', '0'), ('image', '0'), ('ring', '0'),
                           ('segments', 0), ('released', True), ('sent', True), ('failed', True)):
            held, final = self.records()
            held[key] = value
            self.assertTrue(self.verify(held, final))
        for key, value in (('sent', False), ('send_result', -28), ('probed', False),
                           ('probe_result', 0), ('failed', True)):
            held, final = self.records()
            final[key] = value
            self.assertTrue(self.verify(held, final))
        held, final = copy.deepcopy(self.records())
        final['events'][3]['point'], final['events'][4]['point'] = 5, 4
        self.assertTrue(self.verify(held, final))


if __name__ == '__main__':
    unittest.main()
