#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Live proc parsing and fail-closed evidence gates, not native qualification."""
import importlib
import json
from pathlib import Path
import tempfile
import unittest
import contextlib
import io
import socket
import threading

import test_verify_x86_child as halt_fixture
import test_verify_x86_nested as nested_fixture

NONCE = '1234567890abcdef'
BOOT = 'a84d9504-2322-4ec3-94cc-f7cf9c19fddb'


def final_marker():
    return 'MK_X86_CHILD_LOCKDEP_FINAL ' + json.dumps(
        dict(nonce=NONCE, boot_id=BOOT, debug_locks=1)) + '\n'


class LockdepEvidence(unittest.TestCase):
    def test_duplicate_json_key_cannot_hide_disabled_value(self):
        for fixture, text in self.samples():
            for line in text.splitlines(keepends=True):
                if '"debug_locks": 1' in line:
                    self.assertTrue(fixture.verify(text.replace(line, line.replace(
                        '"debug_locks": 1', '"debug_locks": 0, "debug_locks": 1'))))

    def test_admission_sample_must_precede_worker_release(self):
        import test_verify_x86_admission as fixture_module
        fixture = fixture_module.AdmissionGate()
        lines = fixture.trace()
        final = next(line for line in lines if line.startswith('MK_X86_CHILD_LOCKDEP_FINAL '))
        lines.remove(final)
        late = next(index for index, line in enumerate(lines)
                    if line.startswith('MK_X86_ADMISSION_COMPLETE '))
        lines.insert(late, final)
        self.assertTrue(fixture.verify(''.join(lines)), 'post-release lockdep sample accepted')

    def samples(self):
        for fixture in (halt_fixture.X86ChildGate(), nested_fixture.NestedPoolGate()):
            lines = []
            for line in fixture.trace():
                if line.startswith(('MK_X86_BEGIN ', 'MK_X86_NESTED_BEGIN ',
                                    'MK_X86_CHILD_ALIVE ', 'MK_X86_HOST_SURVIVED ',
                                    'MK_X86_NESTED_HOST_SURVIVED ')):
                    name, _, payload = line.partition(' ')
                    line = name + ' ' + json.dumps(dict(json.loads(payload), debug_locks=1)) + '\n'
                lines.append(line)
            text = ''.join(lines)
            if 'MK_X86_CHILD_LOCKDEP_FINAL ' not in text:
                text = text.replace('Instance 1 (native-child) halted',
                                    final_marker() + 'Instance 1 (native-child) halted')
            yield fixture, text

    def test_complete_boundary_evidence(self):
        for fixture, text in self.samples():
            self.assertEqual(fixture.verify(text), [])

    def test_missing_disabled_malformed_or_duplicate_values_fail(self):
        for fixture, text in self.samples():
            for line in text.splitlines(keepends=True):
                if '"debug_locks"' not in line:
                    continue
                name, _, payload = line.partition(' ')
                value = json.loads(payload)
                for bad in (None, 0, True, '1', 2):
                    changed = dict(value)
                    if bad is None:
                        changed.pop('debug_locks')
                    else:
                        changed['debug_locks'] = bad
                    mutated = text.replace(line, name + ' ' + json.dumps(changed) + '\n')
                    with self.subTest(marker=name, bad=bad):
                        self.assertTrue(fixture.verify(mutated), 'invalid live lockdep evidence accepted')
            final = next(line for line in text.splitlines(keepends=True)
                         if line.startswith('MK_X86_CHILD_LOCKDEP_FINAL '))
            for changed in ('', final * 2, final.replace(NONCE, 'fedcba0987654321'),
                            final.replace(BOOT, '62c2429a-bf11-48d8-b06f-7442b072e625')):
                self.assertTrue(fixture.verify(text.replace(final, changed)))
            # A late/replayed final read cannot establish pre-stop child state.
            self.assertTrue(fixture.verify(text.replace(final, '') + final))
            self.assertTrue(fixture.verify(final + text.replace(final, '')))

    def test_proc_reader_requires_exactly_one_enabled_field(self):
        self.assertIsNotNone(importlib.util.find_spec('x86_lockdep'), 'live lockdep reader missing')
        reader = importlib.import_module('x86_lockdep').read_debug_locks
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lockdep_stats'
            with self.assertRaises(OSError):
                reader(path)
            path.write_text(' lock-classes: 42\n debug_locks:                   1\n other: 0\n')
            self.assertEqual(reader(path), 1)
            for text in ('', 'debug_locks: 0\n', 'debug_locks: 2\n',
                         'debug_locks: true\n', 'debug_locks: 1 trailing\n',
                         'debug_locks: 1\ndebug_locks: 1\n',
                         'debug_locks: 1\ndebug_locks: bad\n'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(RuntimeError):
                    reader(path)

    def test_frozen_verifier_requires_each_strict_debug_option(self):
        from verify_x86_child import validate_bundle
        options = ['CONFIG_LOCKDEP=y', 'CONFIG_PROVE_LOCKING=y',
                   'CONFIG_PROVE_RAW_LOCK_NESTING=y', 'CONFIG_PROVE_RCU=y',
                   'CONFIG_PROVE_RCU_LIST=y', 'CONFIG_DEBUG_ATOMIC_SLEEP=y',
                   'CONFIG_DEBUG_PREEMPT=y']
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for missing in options:
                (bundle / 'kernel.config').write_text('\n'.join(v for v in options if v != missing))
                with self.subTest(missing=missing):
                    self.assertEqual(validate_bundle(bundle, '0' * 40),
                                     ['strict lockdep build configuration missing'])

    def test_live_probe_correlates_reply_and_keeps_existing_diagnostics(self):
        self.assertIsNotNone(importlib.util.find_spec('x86_lockdep'), 'live probe missing')
        probe = importlib.import_module('x86_lockdep').probe_child
        for reply, valid in ((final_marker(), True),
                             (final_marker().replace(NONCE, 'fedcba0987654321'), False),
                             (final_marker().replace('"debug_locks": 1', '"debug_locks": 0'), False),
                             (final_marker().replace('"debug_locks": 1', '"debug_locks": true'), False),
                             (final_marker().replace('"debug_locks": 1', '"debug_locks": 0, "debug_locks": 1'), False),
                             ('MK_X86_FAIL {"error":"lockdep disabled"}\n', False)):
            with contextlib.ExitStack() as stack:
                local, remote = socket.socketpair()
                stack.enter_context(local)
                stack.enter_context(remote)
                request = []
                def peer():
                    request.append(remote.recv(1024))
                    remote.sendall(reply.encode())
                    remote.shutdown(socket.SHUT_WR)
                task = threading.Thread(target=peer)
                task.start()
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    try:
                        if valid:
                            self.assertEqual(probe(local.fileno(), b'preexisting diagnostic\n', NONCE), b'')
                        else:
                            with self.assertRaises(RuntimeError):
                                probe(local.fileno(), b'', NONCE)
                    finally:
                        task.join(2)
                self.assertFalse(task.is_alive())
                self.assertEqual(request, [b'lockdep 1234567890abcdef\n'])
                if valid:
                    self.assertTrue(output.getvalue().startswith('preexisting diagnostic\n'))


if __name__ == '__main__':
    unittest.main()
