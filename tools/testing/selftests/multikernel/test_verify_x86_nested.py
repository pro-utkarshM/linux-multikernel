#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject incomplete nested-pool prerequisites before qualifying races."""
import importlib.util
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

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
                      'general protection fault, probably for non-canonical address\n',
                      'Oops: invalid opcode: 0000 [#1]\n',
                      'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:\n',
                      'multikernel: fault while parked, CPU halted\n',
                      'Sent NMI to 3 CPUs in instance 1\n'):
            self.assertTrue(self.verify(''.join(self.trace()) + error))

    def test_out_of_order_and_stale_reply_are_rejected(self):
        lines = self.trace()
        lines[5], lines[6] = lines[6], lines[5]
        self.assertTrue(self.verify(''.join(lines)))
        lines = self.trace()
        lines[6] = lines[6].replace('1234567890abcdef', 'ffffffffffffffff')
        self.assertTrue(self.verify(''.join(lines)))

    def test_bundle_requires_nested_profile_and_observation_config(self):
        import verify_x86_nested as verifier
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            paths = {'.config': 'kernel.config', 'vmlinux': 'rootfs/payload/vmlinux',
                     'arch/x86/boot/bzImage': 'bzImage'}
            for profile, enabled in (('nested', True), ('halt', True),
                                     (None, True), ('nested', False)):
                with self.subTest(profile=profile, enabled=enabled):
                    config = 'CONFIG_MULTIKERNEL=y\nCONFIG_DEBUG_FS=y\n'
                    if enabled:
                        config += 'CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST=y\n'
                    hashes = {}
                    for name, relative in paths.items():
                        path = bundle / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(config if name == '.config' else name)
                        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                    (bundle / 'provenance.json').write_text(json.dumps(
                        {'profile': profile, 'kernel_revision': REVISION}))
                    (bundle / 'mk-x86-build.json').write_text(json.dumps(
                        {'schema': 1, 'revision': REVISION, 'build_exit': 0,
                         'artifacts': hashes}))
                    manifest = ''.join(hashlib.sha256((bundle / relative).read_bytes()).hexdigest()
                                       + '  ' + relative + '\n'
                                       for relative in paths.values())
                    (bundle / 'SHA256SUMS').write_text(manifest)
                    errors = verifier.validate_nested_bundle(bundle, REVISION)
                    self.assertEqual(bool(errors), profile != 'nested' or not enabled)

    def test_host_captures_child_failure_after_retirement_before_unload(self):
        for after_stop in (False, True):
            with self.subTest(after_stop=after_stop):
                self.check_host_captures_late_failure(after_stop)

    def check_host_captures_late_failure(self, after_stop):
        import x86_nested_host_init as host
        outputs = [self.trace()[1].encode(), self.trace()[3].encode(),
                   self.trace()[6].encode()]
        failure = b'MK_X86_FAIL {"error":"late fault"}\n'
        if not after_stop:
            outputs.append(failure)
        calls = []
        def cli(*args):
            calls.append(args)
            if after_stop and args == ('kill', host.NAME):
                outputs.append(failure)
        def text(path, *args, **kwargs):
            if str(path).endswith('/cpu/online'):
                return '0-7' if not calls else '0-2'
            if str(path) == '/payload/source-revision':
                return REVISION
            return '62c2429a-bf11-48d8-b06f-7442b072e625'
        def read(fd, count):
            if outputs:
                return outputs.pop(0)
            raise BlockingIOError()
        clock = iter(index / 10 for index in range(10000))
        with mock.patch.dict(sys.modules, {'kerf.topology': SimpleNamespace(
                logical_to_apic=lambda: dict(enumerate(range(8))))}), \
                mock.patch.object(Path, 'read_text', text), \
                mock.patch.object(host, 'cli', side_effect=cli), \
                mock.patch.object(host, 'ownership', return_value=[3, 4, 5]), \
                mock.patch.object(host, 'status', side_effect=lambda value: value), \
                mock.patch.object(host.secrets, 'token_hex', return_value='1234567890abcdef'), \
                mock.patch.object(host.os, 'open', return_value=7), \
                mock.patch.object(host.os, 'write', side_effect=lambda fd, value: len(value)), \
                mock.patch.object(host.os, 'read', side_effect=read), \
                mock.patch.object(host.os, 'close'), \
                mock.patch.object(host.time, 'monotonic', side_effect=lambda: next(clock)), \
                mock.patch.object(host.select, 'select', side_effect=lambda *args:
                                  ([7], [], []) if outputs else ([], [], [])), \
                contextlib.redirect_stdout(io.StringIO()) as captured:
            with self.assertRaisesRegex(RuntimeError, 'child.*failure|child.*reported failure'):
                host.workload()
        self.assertIn('late fault', captured.getvalue())
        self.assertNotIn(('unload', host.NAME), calls)


if __name__ == '__main__':
    unittest.main()
