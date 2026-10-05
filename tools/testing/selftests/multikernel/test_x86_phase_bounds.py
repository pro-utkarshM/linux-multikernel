#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Whole valid phase blocks must not be accepted outside their lifecycle."""
import json
import unittest
import test_verify_x86_nested as nested_fixture
import test_verify_x86_rcu as rcu_fixture
import test_verify_x86_registry as registry_fixture
import test_verify_x86_tty as tty_fixture
import test_verify_x86_admission as admission_fixture
import verify_x86_rcu
import verify_x86_registry
import verify_x86_tty
import verify_x86_admission
import test_x86_kmsg as kmsg_fixture


class PhaseBounds(unittest.TestCase):
    def test_valid_phase_cannot_move_before_prerequisite_or_after_halt(self):
        nonce = '1234567890abcdef'
        def mark(name, **fields):
            return 'MK_X86_' + name + ' ' + json.dumps(dict(nonce=nonce, **fields)) + '\n'
        for profile in ('rcu', 'registry-replace', 'registry-cleanup', 'tty', 'admission'):
            with self.subTest(profile=profile):
                nested = nested_fixture.NestedPoolGate().trace()
                head, tail = nested[:7], nested[7:]
                if profile == 'rcu':
                    held, final = rcu_fixture.NativeRcuOracle().records()
                    middle = [mark('RCU_HELD', state=held), mark('RCU_COMPLETE', state=final)]
                    check = verify_x86_rcu.verify
                elif profile.startswith('registry-'):
                    mode = profile.removeprefix('registry-')
                    held, final = registry_fixture.RegistryOracle().records(mode)
                    middle = [mark('REGISTRY_HELD', mode=mode, state=held),
                              mark('REGISTRY_COMPLETE', mode=mode, state=final)]
                    if mode == 'cleanup':
                        middle += [mark('REGISTRY_RETAINED', assigned_cpus=[3, 4, 5],
                                        status='active', reclamation='not-attempted')]
                        tail = nested[10:]
                    check = lambda trace, rev: verify_x86_registry.verify(trace, rev, mode)
                elif profile == 'tty':
                    held, final = tty_fixture.TtyOracle().records()
                    middle = [mark('TTY_BEGIN', taint=0), mark('TTY_HELD', state=held),
                              mark('TTY_COMPLETE', state=final, taint=0)]
                    middle += kmsg_fixture.transfer()
                    middle += [
                              mark('TTY_CHILD_HEALTH', taint=0, online_cpus=[3, 4, 5],
                                   boot_id='a84d9504-2322-4ec3-94cc-f7cf9c19fddb')]
                    check = verify_x86_tty.verify
                else:
                    whole = admission_fixture.AdmissionGate().trace()
                    head, middle, tail = whole[:7], whole[7:-5], whole[-5:]
                    check = verify_x86_admission.verify
                tail = [line.replace('nested-pool-prerequisite', 'native-' + profile) for line in tail]
                self.assertEqual(check(''.join(head + middle + tail), nested_fixture.REVISION), [])
                for bad in (middle + head + tail, head + tail + middle):
                    self.assertTrue(check(''.join(bad), nested_fixture.REVISION))


if __name__ == '__main__':
    unittest.main()
