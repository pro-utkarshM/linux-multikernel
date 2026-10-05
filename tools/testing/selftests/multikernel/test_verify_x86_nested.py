#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject incomplete nested-pool prerequisites before qualifying races."""
import importlib.util
import json
from pathlib import Path
import unittest

REVISION = '1234567890abcdef1234567890abcdef12345678'


class NestedPoolGate(unittest.TestCase):
    def verify(self, trace):
        path = Path(__file__).with_name('verify_x86_nested.py')
        self.assertTrue(path.is_file(), 'nested gate verifier is missing')
        spec = importlib.util.spec_from_file_location('verify_x86_nested', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify(trace, expected_revision=REVISION)

    def trace(self):
        def event(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        return [
            event('NESTED_BEGIN', host_cpus=[0, 1, 2], child_cpus=[3, 4, 5],
                  spare_cpus=[6, 7], revision=REVISION),
            event('CHILD_ALIVE', pid=1, instance=1, physical_cpus=[3, 4, 5],
                  online='0-2', boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb'),
            event('PING', nonce='1234567890abcdef'),
            event('CHILD_REPLY', nonce='1234567890abcdef'),
            event('NESTED_POOL_READY', nonce='1234567890abcdef', cpu=5,
                  online_cpus=[3, 4], owned_cpus=[3, 4], pool_cpus=[5],
                  slot='45001000', park='45002000', chunks=[[1157627904, 16777216]]),
            event('NESTED_CPU_RETURNED', nonce='1234567890abcdef', cpu=5,
                  online_cpus=[3, 4, 5], owned_cpus=[3, 4, 5], pool_cpus=[],
                  transaction=1, status='applied'),
            event('NESTED_POOL_RETIRED', nonce='1234567890abcdef', cpu=5,
                  online_cpus=[3, 4, 5], owned_cpus=[3, 4, 5], pool_cpus=[],
                  slot='0', park='0', chunks=[], transaction=2, status='applied'),
            'Instance 1 (native-child) halted, all CPUs confirmed parked\n',
            event('NESTED_HALTED', status='loaded', assigned_cpus=[3, 4, 5]),
            event('NESTED_UNLOADED', status='ready', assigned_cpus=[3, 4, 5]),
            event('NESTED_HOST_SURVIVED', online='0-2',
                  boot_id='62c2429a-bf11-48d8-b06f-7442b072e625'),
            event('NESTED_PASS', slice='nested-pool-prerequisite'),
        ]

    def test_complete_roundtrip_is_accepted(self):
        self.assertEqual(self.verify(''.join(self.trace())), [])

    def test_each_checkpoint_is_mandatory(self):
        lines = self.trace()
        for index in range(len(lines)):
            with self.subTest(index=index):
                self.assertTrue(self.verify(''.join(lines[:index] + lines[index + 1:])))

    def test_reject_false_return_reclaim_and_wrong_identity(self):
        mutations = (
            ('"owned_cpus": [3, 4, 5]', '"owned_cpus": [3, 4]'),
            ('"online_cpus": [3, 4, 5]', '"online_cpus": [3, 4]'),
            ('"pool_cpus": []', '"pool_cpus": [5]'),
            ('"slot": "0"', '"slot": "45001000"'),
            ('"park": "0"', '"park": "45002000"'),
            ('"chunks": []', '"chunks": [[1157627904, 16777216]]'),
            ('"status": "applied"', '"status": "failed"'),
            ('"transaction": 2', '"transaction": 1'),
            ('"cpu": 5', '"cpu": 50'),
            ('"pid": 1', '"pid": true'),
            ('"instance": 1', '"instance": true'),
            ('"child_cpus": [3, 4, 5]', '"child_cpus": [2, 4, 5]'),
            ('"nonce": "1234567890abcdef"', '"nonce": 1234567890123456'),
            (REVISION, '0' * 40),
            ('"online": "0-2"', '"online": "0-1"'),
        )
        for before, after in mutations:
            with self.subTest(after=after):
                self.assertTrue(self.verify(''.join(self.trace()).replace(before, after)))

    def test_failures_or_forced_recovery_do_not_qualify_normal_roundtrip(self):
        for error in ('MK_X86_FAIL {"error":"timeout"}\n',
                      'Kernel panic - not syncing: fault\n',
                      'WARNING: CPU: 1 native_test\n',
                      'BUG: sleeping function called from invalid context\n',
                      'Sent NMI to 3 CPUs in instance 1\n'):
            self.assertTrue(self.verify(''.join(self.trace()) + error))

    def test_out_of_order_and_stale_reply_are_rejected(self):
        lines = self.trace()
        lines[5], lines[6] = lines[6], lines[5]
        self.assertTrue(self.verify(''.join(lines)))
        lines = self.trace()
        lines[6] = lines[6].replace('1234567890abcdef', 'ffffffffffffffff')
        self.assertTrue(self.verify(''.join(lines)))


if __name__ == '__main__':
    unittest.main()
