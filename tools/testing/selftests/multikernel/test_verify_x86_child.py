#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The native boot gate must not accept pre-spawn or incomplete evidence."""
import importlib.util
import json
import inspect
from pathlib import Path
import unittest


class X86ChildGate(unittest.TestCase):
    def verify(self, trace, halt=None):
        spec = importlib.util.spec_from_file_location(
            'verify_x86_child', Path(__file__).with_name('verify_x86_child.py'))
        self.assertTrue(spec.origin and Path(spec.origin).is_file(),
                        'native executing-child verifier has not been implemented')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if halt is not None:
            self.assertIn('halt', inspect.signature(module.verify).parameters,
                          'verifier cannot distinguish forced/voluntary halt evidence')
            return module.verify(trace, halt=halt)
        return module.verify(trace)

    def trace(self):
        def event(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        return [
            event('BEGIN', host_cpus=[0, 1], child_cpus=[2, 3], spare_cpus=[4, 5],
                  revision='c958d01f54750000000000000000000000000000'),
            event('CHILD_ALIVE', pid=1, instance=1, physical_cpus=[2, 3],
                  online='0-1', boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb',
                  release='7.0.0-mk3-test'),
            event('PING', nonce='1234567890abcdef'),
            event('CHILD_REPLY', nonce='1234567890abcdef'),
            'Instance 1 (native-child) halted, all CPUs confirmed parked\n',
            event('HALTED', status='loaded', assigned_cpus=[2, 3]),
            event('UNLOADED', status='ready', assigned_cpus=[2, 3]),
            event('HOST_SURVIVED', online='0-1', boot_id='62c2429a-bf11-48d8-b06f-7442b072e625'),
            event('PASS', slice='executing-child-boot'),
        ]

    def test_complete_boot_gate_is_accepted(self):
        self.assertEqual(self.verify(''.join(self.trace())), [])

    def test_pre_spawn_smoke_is_not_native_child_proof(self):
        self.assertTrue(self.verify('MK_ADAPTER_SMOKE_PASS secondary_started=False\n'))

    def test_each_required_event_must_be_present(self):
        trace = self.trace()
        for index in range(len(trace)):
            with self.subTest(index=index):
                self.assertTrue(self.verify(''.join(trace[:index] + trace[index + 1:])))

    def test_wrong_or_stale_reply_is_rejected(self):
        trace = self.trace()
        trace[3] = trace[3].replace('1234567890abcdef', 'ffffffffffffffff')
        self.assertTrue(self.verify(''.join(trace)))
        trace = self.trace()
        trace[2], trace[3] = trace[3], trace[2]
        self.assertTrue(self.verify(''.join(trace)))

    def test_unbooted_secondary_and_wrong_ownership_are_rejected(self):
        for old, new in (('"online": "0-1"', '"online": "0"'),
                         ('"physical_cpus": [2, 3]', '"physical_cpus": [2, 4]'),
                         ('"pid": 1', '"pid": 42'),
                         ('"spare_cpus": [4, 5]', '"spare_cpus": [3, 5]'),
                         ('"assigned_cpus": [2, 3]', '"assigned_cpus": [2]')):
            with self.subTest(new=new):
                self.assertTrue(self.verify(''.join(self.trace()).replace(old, new)))

    def test_fail_marker_or_panic_cannot_be_hidden_by_pass(self):
        for failure in ('MK_X86_FAIL {"error":"timeout"}\n',
                        'Kernel panic - not syncing: init failed\n'):
            self.assertTrue(self.verify(''.join(self.trace()) + failure))

    def test_requested_halt_cannot_qualify_force_halt(self):
        self.assertTrue(self.verify(''.join(self.trace()), halt='force'))

    def test_force_halt_requires_nmi_to_both_cpus_before_confirmation(self):
        trace = self.trace()
        trace[4] = 'Sent NMI to 2 CPUs in instance 1\n' + trace[4]
        trace[5] = trace[5].replace('"status":', '"mode": "force", "status":')
        self.assertEqual(self.verify(''.join(trace), halt='force'), [])
        self.assertTrue(self.verify(''.join(trace).replace('NMI to 2', 'NMI to 1'),
                                    halt='force'))

    def test_voluntary_halt_requires_the_matching_child_request(self):
        for halt in ('poweroff', 'reboot'):
            trace = self.trace()
            trace[4] = ('MK_X86_TERMINATION_REQUEST ' + json.dumps({'mode': halt})
                        + '\n' + trace[4])
            trace[5] = trace[5].replace('"status":', f'"mode": "{halt}", "status":')
            self.assertEqual(self.verify(''.join(trace), halt=halt), [])
            self.assertTrue(self.verify(''.join(self.trace()), halt=halt))


if __name__ == '__main__':
    unittest.main()
