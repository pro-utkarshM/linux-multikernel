#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject premature persistent allocation free; literal fixtures only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import test_verify_x86_nested as nested_fixture


class DestroyOracle(unittest.TestCase):
    def test_trace_requires_removal_and_pool_return_before_release(self):
        import verify_x86_destroy as verifier
        self.assertTrue(callable(getattr(verifier, 'verify', None)), 'destruction trace gate missing')
        nested = nested_fixture.NestedPoolGate().trace()
        held, final = self.records()
        initial = dict(held, retired=False, probed=False, probe_result=0, events=held['events'][:1])
        def mark(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        armed = mark('DESTROY_ARMED', nonce=held['cookie'], state=initial, taint=0)
        middle = [mark('DESTROY_HELD', nonce=held['cookie'], state=held, transaction=3,
                       status='applied', instance_absent=True, pool_cpus=[3, 4, 5, 6, 7]),
                  mark('DESTROY_COMPLETE', nonce=held['cookie'], state=final, taint=0)]
        trace = ''.join(nested[:9] + [armed, nested[9]] + middle + nested[10:]).replace(
            'nested-pool-prerequisite', 'native-destroy')
        self.assertEqual(verifier.verify(trace, nested_fixture.REVISION), [])
        for bad in (trace.replace('"instance_absent": true', '"instance_absent": false'),
                    trace.replace('"pool_cpus": [3, 4, 5, 6, 7]', '"pool_cpus": [6, 7]'),
                    trace.replace('"transaction": 3', '"transaction": 0'),
                    trace.replace('"status": "applied"', '"status": "failed"'),
                    trace.replace(armed, '') + armed):
            self.assertTrue(verifier.verify(bad, nested_fixture.REVISION))

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
