#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The native boot gate must not accept pre-spawn or incomplete evidence."""
import importlib.util
import json
import inspect
from pathlib import Path
import unittest

REVISION = 'c958d01f54750000000000000000000000000000'


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
            return module.verify(trace, halt=halt, expected_revision=REVISION)
        return module.verify(trace, expected_revision=REVISION)

    def trace(self):
        def event(name, **fields):
            if name in ('BEGIN', 'CHILD_ALIVE', 'HOST_SURVIVED', 'CHILD_LOCKDEP_FINAL'):
                fields['debug_locks'] = 1
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        return [
            event('BEGIN', host_cpus=[0, 1], child_cpus=[2, 3], spare_cpus=[4, 5],
                  revision='c958d01f54750000000000000000000000000000'),
            event('CHILD_ALIVE', pid=1, instance=1, physical_cpus=[2, 3],
                  online='0-1', boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb',
                  release='7.0.0-mk3-test'),
            event('PING', nonce='1234567890abcdef'),
            event('CHILD_REPLY', nonce='1234567890abcdef'),
            (event('CHILD_LOCKDEP_FINAL', nonce='1234567890abcdef',
                   boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb') +
             'Instance 1 (native-child) halted, all CPUs confirmed parked\n' +
             event('CHILD_CAPTURED', nonce='1234567890abcdef', pending_bytes=0)),
            event('HALTED', mode='requested', status='loaded', assigned_cpus=[2, 3]),
            event('UNLOADED', status='ready', assigned_cpus=[2, 3]),
            event('HOST_SURVIVED', online='0-1', boot_id='62c2429a-bf11-48d8-b06f-7442b072e625'),
            event('PASS', slice='executing-child-boot'),
        ]

    def test_complete_boot_gate_is_accepted(self):
        self.assertEqual(self.verify(''.join(self.trace())), [])

    def mailbox_trace(self):
        def event(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'
        allocation = dict(image='1000', ring='2000', ring_phys='3000',
                          control='4000', context='5000', pool='6000',
                          pool_size=536870912, state=3)
        before = dict(used=0, cpu=2**64-1, result=0, retry=0, repark=0, elapsed_us=0,
                      selected_state=0, pool_state=0, tracked=0, tracked_count=2,
                      instance_slot='5000', instance_park='7000',
                      pool_slot='8000', pool_park='9000', pool_cr3='a000')
        after = dict(before, used=1, cpu=3, result=-110, retry=-16, repark=-16,
                     elapsed_us=1000010, selected_state=4, pool_state=4, tracked=1)
        sample = dict(allocations=allocation, owned_cpus=[2, 3], fail_cpu=2**64-1,
                      failures=0)
        trace = self.trace()
        return ''.join(trace[:4]) + ''.join([
            event('MAILBOX_BEFORE', **sample, mailbox=before),
            'mk_spawn: confirm parked: CPU (APIC 3) unconfirmed on slot 0x00005000; quarantined until host reboot\n',
            event('MAILBOX_TIMEOUT', nonce='1234567890abcdef', mailbox=after),
            trace[4].split('Instance 1')[0],
            event('CONSOLE_CLOSED', nonce='1234567890abcdef'),
            "Overlay tx3: Failed to remove instance 'native-child': -16\n",
            event('MAILBOX_RETAINED', **sample, mailbox=after, status='active',
                  exec_errno=16, unload_errno=16, destroy_status='failed', destroy_transaction=3),
            trace[7], event('PASS', slice='mailbox-timeout-retention'),
        ])

    def test_real_mailbox_timeout_is_accepted_without_reclamation(self):
        self.assertEqual(self.verify(self.mailbox_trace(), halt='mailbox-timeout'), [])

    def test_mailbox_gate_rejects_early_injection_or_missing_quarantine(self):
        for old, new in (('"selected_state": 4', '"selected_state": 0'),
                         ('"pool_state": 4', '"pool_state": 0'),
                         ('"elapsed_us": 1000010', '"elapsed_us": 1'),
                         ('"result": -110', '"result": 0'),
                         ('"retry": -16', '"retry": 0'),
                         ('"repark": -16', '"repark": 0'),
                         ('"tracked": 1', '"tracked": 0'),
                         ('"tracked_count": 2', '"tracked_count": 1'),
                         ('"failures": 0', '"failures": 1'),
                         ('"exec_errno": 16', '"exec_errno": 0'),
                         ('"context": "5000"', '"context": "0"'),
                         ('"pool_park": "9000"', '"pool_park": "0"'),
                         ('CPU (APIC 3)', 'CPU (APIC 2)'),
                         ('slot 0x00005000', 'slot 0x00008000')):
            with self.subTest(new=new):
                self.assertTrue(self.verify(self.mailbox_trace().replace(old, new),
                                            halt='mailbox-timeout'))
        trace = self.mailbox_trace()
        for line in trace.splitlines(keepends=True):
            if line.startswith(('MK_X86_MAILBOX_', 'mk_spawn:', 'MK_X86_CONSOLE_CLOSED')):
                self.assertTrue(self.verify(trace.replace(line, ''), halt='mailbox-timeout'))
                self.assertTrue(self.verify(trace + line, halt='mailbox-timeout'))

    def test_mailbox_gate_rejects_recovery_and_changed_allocations(self):
        trace = self.mailbox_trace()
        for extra in ('MK_X86_TEST_CONFIRM_FAIL phys=3\n',
                      'Instance 1 (native-child) halted, all CPUs confirmed parked\n',
                      'Sent NMI to 2 CPUs in instance 1\n', 'MK_X86_UNLOADED {}\n'):
            self.assertTrue(self.verify(trace + extra, halt='mailbox-timeout'))
        lines = trace.splitlines(keepends=True)
        retained = next(line for line in lines if line.startswith('MK_X86_MAILBOX_RETAINED '))
        for old, new in (('"image": "1000"', '"image": "1001"'),
                         ('"pool_slot": "8000"', '"pool_slot": "8001"')):
            self.assertTrue(self.verify(trace.replace(retained, retained.replace(old, new)),
                                        halt='mailbox-timeout'))
        sample = next(line for line in lines if line.startswith('MK_X86_CHILD_LOCKDEP_FINAL '))
        self.assertTrue(self.verify(sample + trace.replace(sample, ''), halt='mailbox-timeout'))

    def test_mailbox_gate_rejects_malformed_or_uncorrelated_records(self):
        trace = self.mailbox_trace()
        for old, new in (('"used": 1', '"used": true'),
                         ('"used": 1', '"used": 0, "used": 1'),
                         ('"cpu": 3', '"cpu": "3"'),
                         ('"elapsed_us": 1000010', '"elapsed_us": 31000000'),
                         ('"mailbox": {', '"mailbox": null, "invalid": {'),
                         ('"destroy_transaction": 3', '"destroy_transaction": 4'),
                         ('"instance_park": "7000"', '"instance_park": "not-hex"'),
                         ('MK_X86_CONSOLE_CLOSED {"nonce": "1234567890abcdef"}',
                          'MK_X86_CONSOLE_CLOSED {"nonce": "ffffffffffffffff"}')):
            with self.subTest(new=new):
                self.assertTrue(self.verify(trace.replace(old, new), halt='mailbox-timeout'))

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

    def test_debug_diagnostics_cannot_be_hidden_by_pass(self):
        for failure in ('WARNING: possible circular locking dependency detected\n',
                        'BUG: sleeping function called from invalid context\n',
                        'Oops: kernel fault\n', 'general protection fault\n',
                        'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:\n',
                        'watchdog: BUG: soft lockup\n'):
            with self.subTest(failure=failure):
                self.assertTrue(self.verify(''.join(self.trace()) + failure))

    def test_child_capture_after_stop_is_mandatory(self):
        trace = ''.join(self.trace())
        lines = trace.splitlines(keepends=True)
        capture = next(line for line in lines if line.startswith('MK_X86_CHILD_CAPTURED '))
        for bad in (trace.replace(capture, ''), trace.replace(capture, '') + capture,
                    trace.replace('"pending_bytes": 0', '"pending_bytes": 7')):
            self.assertTrue(self.verify(bad))

    def test_requested_halt_cannot_qualify_force_halt(self):
        self.assertTrue(self.verify(''.join(self.trace()), halt='force'))

    def test_force_halt_requires_nmi_to_both_cpus_before_confirmation(self):
        trace = self.trace()
        trace[4] = 'Sent NMI to 2 CPUs in instance 1\n' + trace[4]
        trace[5] = trace[5].replace('"mode": "requested"', '"mode": "force"')
        self.assertEqual(self.verify(''.join(trace), halt='force'), [])
        self.assertTrue(self.verify(''.join(trace).replace('NMI to 2', 'NMI to 1'),
                                    halt='force'))

    def test_voluntary_halt_requires_the_matching_child_request(self):
        for halt in ('halt', 'poweroff', 'reboot'):
            trace = self.trace()
            trace[4] = ('MK_X86_TERMINATION_REQUEST ' + json.dumps({'mode': halt})
                        + '\n' + trace[4])
            trace[5] = trace[5].replace('"mode": "requested"', f'"mode": "{halt}"')
            self.assertEqual(self.verify(''.join(trace), halt=halt), [])
            self.assertTrue(self.verify(''.join(self.trace()), halt=halt))

    def retention_trace(self, halt='force-retain'):
        trace = self.trace()
        allocations = {'image': 'ffff888000001000', 'ring': 'ffff888040001000',
                       'ring_phys': '40001000', 'control': '40002000',
                       'context': '40003000', 'pool': 'ffff888000002000',
                       'pool_size': 536870912, 'state': 3}
        retained = {'fault_cpu': 3, 'status': 'active', 'owned_cpus': [2, 3],
                    'unload_errno': 16, 'destroy_status': 'failed', 'destroy_transaction': 3,
                    'allocations_before': allocations, 'allocations_after': allocations}
        mode = halt.removesuffix('-retain')
        request = 'MK_X86_RETENTION_HALT_REQUEST ' + json.dumps({'mode': mode}) + '\n'
        if mode == 'force':
            request += 'Sent NMI to 2 CPUs in instance 1\n'
        if mode in ('poweroff', 'reboot'):
            request += 'MK_X86_TERMINATION_REQUEST ' + json.dumps({'mode': mode}) + '\n'
        trace[4] = (request +
                    'MK_X86_TEST_CONFIRM_FAIL phys=3\n'
                    'MK_X86_CONFIRM_FAILURE_OBSERVED {"before":0,"after":1,"cpu":3}\n'
                    "Overlay tx3: Failed to remove instance 'native-child': -16\n"
                    'MK_X86_RETAINED ' + json.dumps(retained) + '\n'
                    'MK_X86_CONFIRM_FAULT_CLEAR {"cpu":3}\n'
                    'Sent NMI to 2 CPUs in instance 1\n' + trace[4])
        trace[5] = trace[5].replace('"mode": "requested"', f'"mode": "{halt}"')
        return ''.join(trace)

    def test_failed_confirmation_retains_every_allocation_and_refuses_reclaim(self):
        self.assertEqual(self.verify(self.retention_trace(), halt='force-retain'), [])

    def test_requested_and_voluntary_confirmation_failures_cannot_be_qualified_by_force(self):
        for halt in ('requested-retain', 'poweroff-retain', 'reboot-retain'):
            with self.subTest(halt=halt):
                self.assertEqual(self.verify(self.retention_trace(halt), halt=halt), [])
                self.assertTrue(self.verify(self.retention_trace(), halt=halt))

    def test_retention_cannot_accept_missing_injection_or_changed_allocations(self):
        for old, new in (('MK_X86_TEST_CONFIRM_FAIL phys=3', 'other failure'),
                         ('MK_X86_TEST_CONFIRM_FAIL phys=3', 'MK_X86_TEST_CONFIRM_FAIL phys=30'),
                         ('"unload_errno": 16', '"unload_errno": 0'),
                         ('"destroy_status": "failed"', '"destroy_status": "applied"'),
                         ('"status": "active"', '"status": "loaded"'),
                         ('"image": "ffff888000001000"', '"image": "0000000000000000"'),
                         ('MK_X86_CONFIRM_FAULT_CLEAR', 'OTHER_EVENT')):
            with self.subTest(new=new):
                self.assertTrue(self.verify(self.retention_trace().replace(old, new),
                                            halt='force-retain'))

    def test_reject_wrong_source_pin_and_malformed_identity(self):
        for old, new in ((REVISION, '0' * 40), ('"pid": 1', '"pid": true'),
                         ('"instance": 1', '"instance": true'),
                         ('"mode": "requested", ', ''),
                         ('"nonce": "1234567890abcdef"', '"nonce": 1234567890123456')):
            with self.subTest(new=new):
                self.assertTrue(self.verify(''.join(self.trace()).replace(old, new)))

    def test_healthy_nonforce_lane_rejects_nmi(self):
        for halt in ('requested', 'poweroff', 'reboot'):
            trace = self.trace()
            trace[5] = trace[5].replace('"mode": "requested"', f'"mode": "{halt}"')
            trace[4] = 'Sent NMI to 2 CPUs in instance 1\n' + trace[4]
            if halt != 'requested':
                trace[4] = ('MK_X86_TERMINATION_REQUEST ' + json.dumps({'mode': halt})
                            + '\n' + trace[4])
            self.assertTrue(self.verify(''.join(trace), halt=halt))

    def test_force_retention_requires_separate_recovery_nmi(self):
        trace = self.retention_trace()
        first, separator, rest = trace.partition('Sent NMI to 2 CPUs in instance 1\n')
        self.assertTrue(self.verify(first + separator + rest.replace(
            'Sent NMI to 2 CPUs in instance 1\n', ''), halt='force-retain'))

    def test_voluntary_retention_request_must_precede_worker_failure(self):
        trace = self.retention_trace('poweroff-retain')
        request = 'MK_X86_TERMINATION_REQUEST {"mode": "poweroff"}\n'
        trace = trace.replace(request, '') + request
        self.assertTrue(self.verify(trace, halt='poweroff-retain'))
        trace = self.retention_trace('poweroff-retain').replace(
            'MK_X86_CONFIRM_FAILURE_OBSERVED', 'OTHER_EVENT')
        self.assertTrue(self.verify(trace, halt='poweroff-retain'))

    def test_destruction_refusal_must_precede_retention_snapshot(self):
        trace = self.retention_trace()
        refusal = "Overlay tx3: Failed to remove instance 'native-child': -16\n"
        self.assertTrue(self.verify(trace.replace(refusal, '') + refusal, halt='force-retain'))

    def test_physical_fault_id_requires_a_complete_decimal_field(self):
        for suffix in ('-OTHER', '.0'):
            trace = self.retention_trace().replace('phys=3\n', 'phys=3' + suffix + '\n')
            self.assertTrue(self.verify(trace, halt='force-retain'))


if __name__ == '__main__':
    unittest.main()
