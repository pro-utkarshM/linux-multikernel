# SPDX-License-Identifier: GPL-2.0-only
"""Safety refusal checks, never a host reboot or a simulated runtime pass."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
import qemu_kexec_guest as guest

TEST_DIR = Path(__file__).resolve().parent


class KexecRecipeGuards(unittest.TestCase):
    def test_runner_source_override_is_explicit_and_preserves_identity_checks(self):
        # Execute the real preflight; stop before external harness/VM operations.
        runner = TEST_DIR / 'qemu_kexec_test.sh'
        preflight = runner.read_text().split('test "$(git -C "$harness"')[0]
        preflight += '\nprintf "ACCEPTED:%s:%s\\n" "$revision" "${recipe_revision:-missing}"\n'
        recipe = TEST_DIR.parents[3]
        recipe_rev, kernel_rev = 'a' * 40, 'b' * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build, baseline, binaries = root / 'build', root / 'baseline', root / 'bin'
            for path in (build, baseline, binaries):
                path.mkdir()
            # Git is the external boundary: no repository writes in this test.
            git = binaries / 'git'
            git.write_text('''#!/bin/sh
test "$1" = -C || exit 91
case "$2" in
    "$BASELINE_SOURCE") revision=$KERNEL_REV; dirty=$KERNEL_DIRTY ;;
    "$RECIPE_SOURCE") revision=$RECIPE_REV; dirty=$RECIPE_DIRTY ;;
    *) exit 92 ;;
esac
case "$3:$4" in
    status:--porcelain)
        test "$dirty" != error || exit 94
        test "$dirty" = no || echo ' M tracked-file' ;;
    rev-parse:HEAD) echo "$revision" ;;
    rev-parse:--git-common-dir) echo "$TEST_ROOT/bin" ;;
    *) exit 93 ;;
esac
''')
            git.chmod(0o755)
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'],
                       BASELINE_SOURCE=str(baseline), RECIPE_SOURCE=str(recipe),
                       RECIPE_REV=recipe_rev, KERNEL_REV=kernel_rev, TEST_ROOT=str(root))
            cases = (
                ('default', recipe, (), recipe_rev, 'no', 'no', True),
                ('baseline', baseline, (baseline, kernel_rev), kernel_rev, 'no', 'no', True),
                ('implicit baseline', baseline, (), kernel_rev, 'no', 'no', False),
                ('missing revision', baseline, (baseline,), kernel_rev, 'no', 'no', False),
                ('empty revision', baseline, (baseline, ''), kernel_rev, 'no', 'no', False),
                ('empty source', baseline, ('', kernel_rev), kernel_rev, 'no', 'no', False),
                ('wrong revision', baseline, (baseline, recipe_rev), kernel_rev, 'no', 'no', False),
                ('symbolic revision', baseline, (baseline, 'HEAD'), kernel_rev, 'no', 'no', False),
                ('wrong source', baseline, (recipe, kernel_rev), kernel_rev, 'no', 'no', False),
                ('stale stamp', baseline, (baseline, kernel_rev), recipe_rev, 'no', 'no', False),
                ('dirty kernel', baseline, (baseline, kernel_rev), kernel_rev, 'yes', 'no', False),
                ('dirty recipe', baseline, (baseline, kernel_rev), kernel_rev, 'no', 'yes', False),
                ('kernel status error', baseline, (baseline, kernel_rev), kernel_rev, 'error', 'no', False),
                ('recipe status error', baseline, (baseline, kernel_rev), kernel_rev, 'no', 'error', False),
                ('extra argument', baseline, (baseline, kernel_rev, 'extra'), kernel_rev, 'no', 'no', False),
            )
            for name, source, override, stamp, kernel_dirty, recipe_dirty, accepted in cases:
                with self.subTest(name=name):
                    link = build / 'source'
                    link.unlink(missing_ok=True)
                    link.symlink_to(source)
                    (build / 'source-revision.txt').write_text(stamp + '\n')
                    result = subprocess.run(
                        ['bash', '-c', preflight, str(runner), str(build)] +
                        [str(root)] * 5 + ['ordinary'] + list(map(str, override)),
                        env=dict(env, KERNEL_DIRTY=kernel_dirty, RECIPE_DIRTY=recipe_dirty),
                        text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    if accepted:
                        self.assertIn(f'ACCEPTED:{stamp}:{recipe_rev}', result.stdout)
                    else:
                        self.assertNotIn('ACCEPTED:', result.stdout)

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
