#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject premature persistent allocation free; literal fixtures only."""
import copy
import importlib.util
from pathlib import Path
import unittest


class DestroyOracle(unittest.TestCase):
    def verify(self, held, final):
        path = Path(__file__).with_name('verify_x86_destroy.py')
        self.assertTrue(path.is_file(), 'native destruction verifier missing')
        spec = importlib.util.spec_from_file_location('verify_x86_destroy', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_records(held, final)

    def records(self):
        def event(point):
            return dict(seq=point, point=point, cpu=0 if point in (1, 7) else 2 if point == 6 else 1,
                        hardirq=False, irqs_off=point == 2)
        held = dict(cookie='1234567890abcdef', instance='ffff0010', image='ffff0020',
                    ring='800000', manifest='900000', pool='ffff0030',
                    released=False, failed=False, retired=True, sent=False,
                    send_result=0, probed=True, probe_result=-22,
                    events=[event(i) for i in range(1, 6)])
        final = dict(held, released=True, sent=True, events=[event(i) for i in range(1, 12)])
        return held, final

    def test_valid_literal_deferred_reclamation(self):
        self.assertEqual(self.verify(*self.records()), [])

    def test_every_boundary_required_and_reference_is_not_pool_pin(self):
        for index in range(11):
            held, final = self.records()
            final['events'].pop(index)
            self.assertTrue(self.verify(held, final))
        for key, value in (('ring', '0'), ('manifest', '0'), ('pool', '0'),
                           ('retired', False), ('released', True), ('sent', True),
                           ('probed', False), ('probe_result', 0), ('failed', True)):
            held, final = self.records()
            held[key] = value
            self.assertTrue(self.verify(held, final))
        held, final = copy.deepcopy(self.records())
        final['events'][6]['point'], final['events'][9]['point'] = 10, 7
        self.assertTrue(self.verify(held, final))


if __name__ == '__main__':
    unittest.main()
