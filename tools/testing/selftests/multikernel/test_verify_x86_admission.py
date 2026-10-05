#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Literal oracle fixtures, never native proof."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import test_verify_x86_nested as nested_fixture


class AdmissionGate(unittest.TestCase):
    def test_parent_pool_readback_is_a_canonical_physical_set(self):
        import x86_admission_host_init as host
        with mock.patch.object(Path, 'read_text', return_value=json.dumps(
                dict(instance=0, pool_cpus=[6, 7, 5]))):
            self.assertEqual(host.pool_cpus(), [5, 6, 7])
        for ids in ([5, 5], [True, 6], [-1, 6]):
            with self.subTest(ids=ids), mock.patch.object(Path, 'read_text', return_value=json.dumps(
                    dict(instance=0, pool_cpus=ids))):
                with self.assertRaises(RuntimeError):
                    host.pool_cpus()

    def verify(self, text):
        path = Path(__file__).with_name('verify_x86_admission.py')
        self.assertTrue(path.is_file(), 'admission verifier missing')
        spec = importlib.util.spec_from_file_location('verify_x86_admission', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify(text, nested_fixture.REVISION)

    def trace(self):
        lines = nested_fixture.NestedPoolGate().trace()
        result = lines[:7]
        nonce = '1234567890abcdef'
        sequence = 0
        def mark(name, **fields):
            result.append('MK_X86_' + name + ' ' + json.dumps(dict(nonce=nonce, **fields)) + '\n')
        def native(point, request=0, cpu=0, status=0, operation=0):
            nonlocal sequence
            sequence += 1
            result.append('MK_X86_NATIVE ' + json.dumps(dict(seq=sequence, instance=1,
                point=point, request=request, cpu=cpu, result=status, operation=operation)) + '\n')
            return dict(seq=sequence, point=point, request=request, cpu=cpu,
                        result=status, operation=operation)
        def cpu(request, cpu=5, op=8194):
            native(2, request, cpu, operation=op)
            native(3, request, cpu, operation=op)
            native(5, request, cpu, operation=op)
        state = dict(owned_cpus=[3, 4, 5], online_cpus=[3, 4, 5], pool_cpus=[],
                     chunks=[], slot='0', park='0')
        for mode in ('controller-first', 'worker-first'):
            mark('ADMISSION_BEGIN', mode=mode, cpu=5)
            if mode == 'controller-first':
                native(8, 4)
                native(1, 4)
                held = native(9, 4, status=1)
                mark('ADMISSION_HELD', mode=mode, event=held, point=1, active=True)
                native(4, 100, 5, -16, 8194)
                native(3, 100, 5, -16, 8194)
                native(5, 100, 5, operation=8194)
                mark('ADMISSION_REJECTED', mode=mode, status='failed', transaction=7,
                     assigned_cpus=[3, 4, 5], pool_cpus=[6, 7])
                native(10, 4)
                native(1, 5)
                mark('ADMISSION_CONTROLLER_DONE', mode=mode, transaction=4, status='applied')
                mark('ADMISSION_RETIRED', mode=mode, status='applied', transaction=5, **state)
                cpu(101)
            else:
                native(2, 103, 5, operation=8194)
                held = native(9, 103, 5, 2, 8194)
                mark('ADMISSION_HELD', mode=mode, event=held, point=2, active=True)
                attempt = native(8, 7)
                mark('ADMISSION_CONTROLLER_WAITING', mode=mode, event=attempt, active=True)
                native(10, 103, 5, operation=8194)
                native(3, 103, 5, operation=8194)
                native(5, 103, 5, operation=8194)
                native(1, 7)
                mark('ADMISSION_CONTROLLER_DONE', mode=mode, transaction=7, status='applied')
                reduced = dict(state, owned_cpus=[3, 4], online_cpus=[3, 4])
                mark('ADMISSION_RETIRED', mode=mode, status='applied', transaction=8, **reduced)
            mark('ADMISSION_REMOVED', mode=mode, status='applied', transaction=9,
                 assigned_cpus=[3, 4], pool_cpus=[5, 6, 7])
            cpu(102 if mode == 'controller-first' else 104, op=8193)
            mark('ADMISSION_SETTLED', mode=mode, status='applied', transaction=10,
                 assigned_cpus=[3, 4, 5], **state)
        mark('ADMISSION_BEGIN', mode='timeout-drain', cpu=6)
        native(2, 105, 6, operation=8193)
        native(3, 105, 6, operation=8193)
        held = native(9, 105, 6, 3, 8193)
        mark('ADMISSION_HELD', mode='timeout-drain', event=held, point=3, active=True)
        result.append("Failed to apply overlay transaction 11: -110\n")
        mark('ADMISSION_TIMEOUT_RETAINED', status='failed', transaction=11,
             assigned_cpus=[3, 4, 5, 6], pool_cpus=[7], unload_errno=16,
             instance_status='active', elapsed_ms=10010,
             child=dict(state, owned_cpus=[3, 4, 5, 6], online_cpus=[3, 4, 5, 6]))
        closed = native(6)
        mark('ADMISSION_DRAIN_WAITING', closed=closed, held=held, active=True)
        native(10, 105, 6, operation=8193)
        native(5, 105, 6, operation=8193)
        native(7)
        mark('ADMISSION_COMPLETE', status='loaded', assigned_cpus=[3, 4, 5, 6])
        result.extend(line.replace('"assigned_cpus": [3, 4, 5]', '"assigned_cpus": [3, 4, 5, 6]')
                      .replace('nested-pool-prerequisite', 'native-admission') for line in lines[7:])
        return result

    def test_complete_literal_is_accepted(self):
        self.assertEqual(self.verify(''.join(self.trace())), [])

    def test_every_acceptance_checkpoint_and_marker_is_required(self):
        lines = self.trace()
        for i, line in enumerate(lines):
            if 'MK_X86_NATIVE' not in line and 'ADMISSION_' not in line:
                continue
            # The fixture includes a retirement controller observation, but
            # retirement is proved by its transaction and allocation readback.
            if '"point": 1, "request": 5' in line:
                continue
            with self.subTest(index=i):
                self.assertTrue(self.verify(''.join(lines[:i] + lines[i + 1:])))

    def test_reject_false_admission_correlation_and_reclaim(self):
        changes = (('"point": 4', '"point": 2'), ('"request": 100', '"request": 0'),
                   ('"result": -16', '"result": 0'), ('"active": true', '"active": false'),
                   ('"unload_errno": 16', '"unload_errno": 0'),
                   ('"pool_cpus": [7]', '"pool_cpus": [6, 7]'),
                   ('"elapsed_ms": 10010', '"elapsed_ms": 10'),
                   ('"point": 7', '"point": 6'), ('"cpu": 6', '"cpu": 60'),
                   ('"slot": "0"', '"slot": "126208000"'),
                   ('"request": 105', '"request": 104'))
        for old, new in changes:
            with self.subTest(new=new):
                self.assertTrue(self.verify(''.join(self.trace()).replace(old, new)))

    def test_timeout_or_fault_cannot_be_hidden_by_pass(self):
        for suffix in ('MK_X86_NATIVE {"instance":1,"point":11}\n',
                       'Oops: late fault\n', 'MK_X86_FAIL {"error":"missing hold"}\n'):
            self.assertTrue(self.verify(''.join(self.trace()) + suffix))


if __name__ == '__main__':
    unittest.main()
