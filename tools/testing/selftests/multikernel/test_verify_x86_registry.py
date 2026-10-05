#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal evidence fixtures, not native registry qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import test_verify_x86_nested as nested_fixture


class RegistryOracle(unittest.TestCase):
    def test_terminal_trace_retains_resources_and_cannot_claim_reclaim(self):
        import verify_x86_registry as verifier
        nested = nested_fixture.NestedPoolGate().trace()
        held, final = self.records('cleanup')
        def mark(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        middle = [mark('REGISTRY_HELD', nonce=held['cookie'], mode='cleanup', state=held),
                  mark('REGISTRY_COMPLETE', nonce=held['cookie'], mode='cleanup', state=final),
                  mark('REGISTRY_RETAINED', assigned_cpus=[3, 4, 5], status='active',
                       reclamation='not-attempted')]
        trace = ''.join(nested[:7] + middle + [nested[7].splitlines(keepends=True)[0]] + nested[10:]).replace(
            'nested-pool-prerequisite', 'native-registry-cleanup')
        self.assertEqual(verifier.verify(trace, nested_fixture.REVISION, 'cleanup'), [])
        for bad in (trace.replace('"status": "active"', '"status": "ready"'),
                    trace + nested[7], trace.replace('"assigned_cpus": [3, 4, 5]',
                                                    '"assigned_cpus": [3, 4]')):
            self.assertTrue(verifier.verify(bad, nested_fixture.REVISION, 'cleanup'))

    def verify(self, held, final, mode):
        path = Path(__file__).with_name('verify_x86_registry.py')
        self.assertTrue(path.is_file(), 'registry evidence verifier missing')
        spec = importlib.util.spec_from_file_location('verify_x86_registry', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_records(held, final, mode)

    def records(self, mode):
        def event(seq, point):
            irq = point in (1, 4, 8, 15)
            return dict(seq=seq, point=point, cpu=0 if irq else 2 if point == 9 else 1,
                        hardirq=irq, vector=irq)
        start = [1, 12, 2, 3, 11]
        end = [9, 4, 8, 5, 6, 13, 7, 14] + ([15] if mode == 'replace' else []) + [8]
        held = dict(cookie='1234567890abcdef', handler='ffff0001', context='ffff0002',
                    type_context='ffff0003', mode=1 if mode == 'replace' else 2,
                    invocations=1, consumed=0, released=False, timed_out=False,
                    waiter_sleeping=True, done=False, overflow=False,
                    registrar_sleeping=True, registration_done=False, registration_result=0,
                    replacement_invocations=0,
                    events=[event(i+1, p) for i, p in enumerate(start)])
        final = dict(held, consumed=2, released=True, waiter_sleeping=False, done=True,
                     registrar_sleeping=False, registration_done=True,
                     registration_result=0 if mode == 'replace' else -108,
                     replacement_invocations=1 if mode == 'replace' else 0,
                     events=[event(i+1, p) for i, p in enumerate(start + end)])
        return held, final

    def test_valid_literal_orders(self):
        for mode in ('replace', 'cleanup'):
            self.assertEqual(self.verify(*self.records(mode), mode), [])

    def test_each_actual_boundary_required(self):
        for mode in ('replace', 'cleanup'):
            for index in range(len(self.records(mode)[1]['events'])):
                held, final = self.records(mode)
                final['events'].pop(index)
                self.assertTrue(self.verify(held, final, mode))

    def test_no_false_contention_or_early_reuse(self):
        for mode in ('replace', 'cleanup'):
            for key, value in (('waiter_sleeping', False), ('registrar_sleeping', False),
                               ('registration_done', True), ('released', True),
                               ('timed_out', True), ('type_context', '0')):
                held, final = self.records(mode)
                held[key] = value
                self.assertTrue(self.verify(held, final, mode), (mode, key))
            for key, value in (('invocations', 2), ('consumed', 1), ('done', False),
                               ('registration_result', -16), ('registration_done', False)):
                held, final = self.records(mode)
                final[key] = value
                self.assertTrue(self.verify(held, final, mode), (mode, key))
            held, final = copy.deepcopy(self.records(mode))
            a = next(e for e in final['events'] if e['point'] == 14)
            b = next(e for e in final['events'] if e['point'] == 13)
            a['point'], b['point'] = b['point'], a['point']
            self.assertTrue(self.verify(held, final, mode))


if __name__ == '__main__':
    unittest.main()
