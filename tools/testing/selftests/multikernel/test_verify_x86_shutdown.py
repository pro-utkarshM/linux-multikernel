#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Permit rejection is not successful halt or injected confirmation failure."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import test_verify_x86_child as boot_fixture

REVISION = boot_fixture.REVISION


def event(name, **fields):
    return 'MK_X86_' + name + ' ' + json.dumps(fields) + '\n'


def trace(mode='panic-retention'):
    initial = boot_fixture.X86ChildGate().trace()
    terminal = dict(nonce='1234567890abcdef', instance=1, notify=0,
                    panic=int(mode == 'panic-retention'), kexec=0, observed=1,
                    busy=int(mode != 'panic-retention'), active=int(mode != 'panic-retention'),
                    valid=int(mode != 'panic-retention'), overflow=0,
                    point=int(mode != 'panic-retention'))
    allocations = dict(image='ffff888000001000', ring='ffff888040001000',
                       ring_phys='40001000', control='40002000', context='40003000',
                       pool='ffff888000002000', pool_size=536870912, state=3)
    before = dict(allocations=allocations, owned_cpus=[2, 3], fail_cpu=2**64-1, failures=0)
    text = ''.join(initial[:4]) + initial[4].split('Instance 1')[0]
    text += event('SHUTDOWN_BEFORE', **before)
    text += event('TERMINATION_REQUEST', mode=mode, nonce='1234567890abcdef')
    text += event('SHUTDOWN_OBSERVED', **terminal)
    text += event('CONSOLE_CLOSED', nonce='1234567890abcdef')
    text += "Overlay tx3: Failed to remove instance 'native-child': -16\n"
    text += event('SHUTDOWN_RETAINED', **before, mode=mode, status='active',
                  exec_errno=16, unload_errno=16, destroy_status='failed', destroy_transaction=3)
    text += initial[-2] + event('PASS', slice='shutdown-permit-rejection')
    return text, event('SHUTDOWN', **terminal)


class ShutdownGate(unittest.TestCase):
    def verify(self, text, debug, mode='panic-retention'):
        path = Path(__file__).with_name('verify_x86_shutdown.py')
        self.assertTrue(path.exists(), 'shutdown-permit verifier not implemented')
        spec = importlib.util.spec_from_file_location('verify_x86_shutdown', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify(text, debug, mode, REVISION)

    def test_both_rejection_lanes_require_real_terminal_observation(self):
        for mode in ('panic-retention', 'contended-poweroff-retention'):
            text, debug = trace(mode)
            self.assertEqual(self.verify(text, debug, mode), [])
            self.assertTrue(self.verify(text, '', mode))
            self.assertTrue(self.verify(text, debug + debug, mode))

    def test_no_settlement_recovery_or_notification_is_allowed(self):
        text, debug = trace()
        for extra in ('Instance 1 (native-child) halted, all CPUs confirmed parked\n',
                      'Sent NMI to 2 CPUs in instance 1\n', 'MK_X86_HALTED {}\n',
                      'MK_X86_UNLOADED {}\n', 'MK_X86_TEST_CONFIRM_FAIL phys=3\n',
                      'MK_X86_FAIL {}\n', 'WARNING: sleeping in atomic\n'):
            with self.subTest(extra=extra):
                self.assertTrue(self.verify(text + extra, debug))

    def test_loss_permit_or_expired_controller_gate_fails(self):
        text, debug = trace('contended-poweroff-retention')
        for old, new in (('"notify": 0', '"notify": 1'), ('"valid": 1', '"valid": 0'),
                         ('"active": 1', '"active": 0'), ('"point": 1', '"point": 2'),
                         ('"busy": 1', '"busy": 0'), ('"overflow": 0', '"overflow": 1'),
                         ('"observed": 1', '"observed": 0')):
            self.assertTrue(self.verify(text.replace(old, new), debug.replace(old, new),
                                        'contended-poweroff-retention'))

    def test_controller_timeout_cannot_hide_behind_a_later_valid_record(self):
        text, debug = trace('contended-poweroff-retention')
        for point in (10, 11):
            self.assertTrue(self.verify(text + event('NATIVE', instance=1, point=point),
                                        debug, 'contended-poweroff-retention'))

    def test_runner_refuses_unfrozen_invocation_without_launching(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('run_x86_shutdown.py')),
                                     '--bundle', directory, '--revision', REVISION,
                                     '--mode', 'panic-retention', '--output', directory],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_refusal_must_follow_terminal_and_console_close(self):
        text, debug = trace()
        lines = text.splitlines(keepends=True)
        for prefix in ('SHUTDOWN_OBSERVED', 'CONSOLE_CLOSED', 'SHUTDOWN_BEFORE'):
            line = next(line for line in lines if line.startswith('MK_X86_' + prefix + ' '))
            self.assertTrue(self.verify(text.replace(line, ''), debug))
            self.assertTrue(self.verify(text.replace(line, '') + line, debug))

    def test_allocations_fault_selector_and_cpu_ownership_are_not_optional(self):
        text, debug = trace()
        for old, new in (('"exec_errno": 16', '"exec_errno": 0'),
                         ('"unload_errno": 16', '"unload_errno": 0'),
                         ('"destroy_status": "failed"', '"destroy_status": "applied"'),
                         ('"status": "active"', '"status": "loaded"'),
                         ('"failures": 0', '"failures": 1'),
                         ('"fail_cpu": 18446744073709551615', '"fail_cpu": 3'),
                         ('"owned_cpus": [2, 3]', '"owned_cpus": [2]'),
                         ('"image": "ffff888000001000"', '"image": "0"')):
            self.assertTrue(self.verify(text.replace(old, new), debug))
        self.assertTrue(self.verify(text.replace('"ring_phys": "40001000"',
                                                '"ring_phys": "50001000"', 1), debug))

    def test_wrong_revision_nonce_duplicate_keys_and_wrong_panic_fail(self):
        text, debug = trace()
        self.assertTrue(self.verify(text.replace(REVISION, '0' * 40), debug))
        self.assertTrue(self.verify(text, debug.replace('1234567890abcdef', 'f' * 16)))
        for old, new in (('"notify": 0', '"notify": 1, "notify": 0'),
                         ('"panic": 1', '"panic": 0')):
            self.assertTrue(self.verify(text.replace(old, new), debug.replace(old, new)))

    def test_cli_does_not_ignore_failed_bundle_validation(self):
        text, debug = trace()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'serial').write_text(text)
            (root / 'debug').write_text(debug)
            result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('verify_x86_shutdown.py')),
                                     '--bundle', str(root), '--revision', REVISION,
                                     '--mode', 'panic-retention', '--debug', str(root / 'debug'),
                                     str(root / 'serial')], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == '__main__':
    unittest.main()
