#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject stale artifacts and non-QEMU execution without launching a VM."""
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REVISION = '1234567890abcdef1234567890abcdef12345678'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class X86Provenance(unittest.TestCase):
    def test_preflight_disables_bytecode_writes(self):
        path = HERE / 'prepare_x86_child.py'
        # Exercise the script body as __main__ would, not import-loader caching.
        # Starting Python with -B must not make this assertion vacuous.
        namespace = {'__file__': str(path), '__name__': 'preflight_bytecode_check'}
        with patch.object(sys, 'dont_write_bytecode', False):
            exec(compile(path.read_text(), str(path), 'exec'), namespace)
            self.assertTrue(sys.dont_write_bytecode)

    def test_qemu_guard_rejects_missing_and_bare_metal_identity(self):
        host = load('x86_host_init')
        self.assertTrue(hasattr(host, 'require_qemu'), 'VM boundary not implemented')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(RuntimeError):
                host.require_qemu(root)
            (root / 'sys_vendor').write_text('Other\n')
            (root / 'product_name').write_text('Standard PC (Q35 + ICH9, 2009)\n')
            with self.assertRaises(RuntimeError):
                host.require_qemu(root)
            (root / 'sys_vendor').write_text('QEMU\n')
            host.require_qemu(root)
            (root / 'product_name').write_text('Other\n')
            with self.assertRaises(RuntimeError):
                host.require_qemu(root)

    def test_build_proof_rejects_missing_wrong_pin_and_changed_artifact(self):
        packer = load('prepare_x86_child')
        self.assertTrue(hasattr(packer, 'validate_build_proof'), 'build binding not implemented')
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            for name in ('.config', 'vmlinux', 'arch/x86/boot/bzImage'):
                path = build / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                packer.validate_build_proof(build, REVISION)
            proof = {'schema': 1, 'revision': REVISION, 'source': '/source',
                     'source_tree': 'a' * 40, 'build_exit': 0,
                     'artifacts': {name: packer.digest(build / name) for name in
                                   ('.config', 'vmlinux', 'arch/x86/boot/bzImage')}}
            (build / 'mk-x86-build.json').write_text(json.dumps(proof))
            self.assertEqual(packer.validate_build_proof(build, REVISION), proof)
            with self.assertRaises(RuntimeError):
                packer.validate_build_proof(build, 'b' * 40)
            (build / 'vmlinux').write_bytes(b'stale or unrelated binary')
            with self.assertRaises(RuntimeError):
                packer.validate_build_proof(build, REVISION)

    def test_bundle_binding_rejects_missing_manifest_wrong_pin_and_changed_binary(self):
        verifier = load('verify_x86_child')
        packer = load('prepare_x86_child')
        self.assertTrue(hasattr(verifier, 'validate_bundle'), 'frozen bundle binding not implemented')
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            self.assertTrue(verifier.validate_bundle(bundle, REVISION))
            names = {'.config': 'kernel.config', 'vmlinux': 'rootfs/payload/vmlinux',
                     'arch/x86/boot/bzImage': 'bzImage'}
            for name in names.values():
                path = bundle / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((
                    'CONFIG_LOCKDEP=y\nCONFIG_PROVE_LOCKING=y\n'
                    'CONFIG_PROVE_RAW_LOCK_NESTING=y\nCONFIG_PROVE_RCU=y\n'
                    'CONFIG_PROVE_RCU_LIST=y\nCONFIG_DEBUG_ATOMIC_SLEEP=y\n'
                    'CONFIG_DEBUG_PREEMPT=y\n' if name == 'kernel.config' else name).encode())
            proof = {'schema': 1, 'revision': REVISION, 'build_exit': 0,
                     'artifacts': {name: packer.digest(bundle / path) for name, path in names.items()}}
            (bundle / 'mk-x86-build.json').write_text(json.dumps(proof))
            (bundle / 'provenance.json').write_text(json.dumps({'kernel_revision': REVISION}))
            files = sorted(path for path in bundle.rglob('*') if path.is_file())
            (bundle / 'SHA256SUMS').write_text(''.join(
                packer.digest(path) + '  ' + str(path.relative_to(bundle)) + '\n' for path in files))
            self.assertEqual(verifier.validate_bundle(bundle, REVISION), [])
            self.assertTrue(verifier.validate_bundle(bundle, 'b' * 40))
            (bundle / 'bzImage').write_bytes(b'unrelated binary')
            self.assertTrue(verifier.validate_bundle(bundle, REVISION))


if __name__ == '__main__':
    unittest.main()
