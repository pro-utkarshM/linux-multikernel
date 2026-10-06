# SPDX-License-Identifier: GPL-2.0-only
"""Safety refusal checks, never a host reboot or a simulated runtime pass."""
from pathlib import Path
import subprocess
import sys
import unittest
import qemu_kexec_guest as guest

TEST_DIR = Path(__file__).resolve().parent


class KexecRecipeGuards(unittest.TestCase):
    def test_target_scope_checks_do_not_fall_through_shell_and_lists(self):
        source = (TEST_DIR / 'qemu-kexec-target').read_text()
        checks = source[source.index('[ "$guard" = vm-v1 ]'):source.index('mount -t sysfs')]
        script = 'set -efu\nguard=$1; stage=$2; mode=$3; token=$4\n' + checks + '\necho ACCEPTED\n'
        for guard, stage, mode, token, accepted in (
                ('vm-v1', 'target', 'ordinary', 'a' * 32, True),
                ('vm-v1', 'target', 'crash', 'a' * 32, True),
                ('wrong', 'target', 'ordinary', 'a' * 32, False),
                ('wrong', 'primary', 'ordinary', 'a' * 32, False),
                ('vm-v1', 'primary', 'ordinary', 'a' * 32, False),
                ('vm-v1', 'target', 'spawn', 'a' * 32, False),
                ('vm-v1', 'target', 'ordinary', 'bad', False)):
            result = subprocess.run(['sh', '-c', script, 'scope-test', guard, stage, mode, token],
                                    text=True, capture_output=True, timeout=5)
            with self.subTest(guard=guard, stage=stage, mode=mode, token=token):
                self.assertEqual(result.returncode == 0, accepted)
                self.assertEqual('ACCEPTED' in result.stdout, accepted)

    def test_scope_must_be_valid_before_shutdown_cleanup_is_allowed(self):
        parse = guest.parse_scope
        token = 'a' * 32
        command = ('console=ttyS0 mk_kexec_guard=vm-v1 mk_kexec_stage=primary '
                   'mk_kexec_mode=ordinary mk_kexec_token=' + token)
        self.assertEqual(parse(command), ('ordinary', token))
        self.assertEqual(parse(command.replace('ordinary', 'crash')), ('crash', token))
        for invalid in ('', command.replace('vm-v1', 'other'),
                        command.replace('primary', 'target'), command.replace('ordinary', 'spawn'),
                        command.replace(token, 'xyz'), command + ' mk_kexec_mode=crash'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid)

    def test_primary_refuses_non_pid1_execution(self):
        result = subprocess.run([sys.executable, '-B', str(TEST_DIR / 'qemu_kexec_guest.py')],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing operations outside RISC-V guest PID1', result.stderr)

    def test_target_refuses_non_pid1_execution(self):
        result = subprocess.run(['sh', str(TEST_DIR / 'qemu-kexec-target')],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing operations outside guest PID1', result.stderr)

    def test_runner_rejects_unknown_mode_before_accessing_inputs(self):
        result = subprocess.run(['bash', str(TEST_DIR / 'qemu_kexec_test.sh')] +
                                ['/nonexistent'] * 6 + ['spawn'],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn('mode must be ordinary or crash', result.stderr)


if __name__ == '__main__':
    unittest.main()
