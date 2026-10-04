# SPDX-License-Identifier: GPL-2.0-only
import importlib
import unittest
from test_verify_lifecycle import event

R = dict(image=0x1000, ctrl=0xd0000000, manifest=0x9000, ring=0xa000,
         pool=0x2000, size=268435456, owned=2, tracked=2)


def snapshot(state='failed'):
    return ('[ 33.0] MK_TEST_RESOURCE id=1 phase=confirm-exit state=' + state +
            ' image=1000 ctrl=d0000000 manifest=9000 ring=a000 pool=2000'
            ' size=268435456 owned=2 tracked=2\n')


def retention_log(mode='failed-retain', fault=8):
    control = ('[ 1.0] MK_TEST_FREE id=1 kind=allocation phys=d0000000 size=4096 pool=2000\n'
               '[ 1.1] MK_TEST_FREE id=1 kind=allocation phys=d0200000 size=4096 pool=2000\n'
               '[ 1.2] MK_TEST_FREE id=1 kind=ring phys=a000 size=8192 pool=2000\n'
               '[ 1.3] MK_TEST_FREE id=1 kind=manifest phys=9000 size=4096 pool=2000\n'
               '[ 1.4] MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000\n')
    text = 'OpenSBI v1.8.1\n' + event('BEGIN', mode=mode, fault=fault, harts=[65537, 7],
                                      cycles=1, images='same', host_boot='host')
    text += event('CONTROL', resources=R, release_log=control, host_alive=True)
    if mode == 'failed-retain':
        text += event('REJECTED', error=1, state='failed', tracer_exercised=True)
        text += 'MK_FW_REJECT mode=8 hart=65537 entry=0x88000000 error=-4\n'
        state='failed'
    else:
        text += ('MK_CHILD_READY online=0-1 present=0-1 possible=0-3 boot=child release=test\n'
                 'MK_CHILD_PONG\n')
        text += event('CHILD', cycle=1, boot='child', assigned=[65537, 7], online=[0, 1],
                      ring_roundtrip=True, active_unload_rejected=True,
                      release='test', image_sha='a'*64, image_start=0xd8000000)
        text += event('TIMEOUT', error=110, state='active', elapsed=30.1,
                      ack=dict(type=12288, operation=12290, resource=1, request=3, result=0))
        text += ('[ 3.0] MK_TEST_ACK_DROPPED type=12288 operation=12290 resource=1 request=3 result=0\n'
                 '[ 33.0] Timeout waiting for operation 0x3002 on resource 1\n')
        state='active'
    guards = {name: dict(error=('failed' if name=='destroy' else 16),
                        trace=['mk_hsm_status: hart=65537 state=3'])
              for name in ('exec', 'unload', 'destroy')}
    guard_log = snapshot(state) + snapshot(state)
    text += event('RETAINED', state=state, harts=[65537, 7], checks=guards,
                  positive_trace=['mk_copy:', 'mk_start:'],
                  resources_before=R, resources_after=R, guard_log=guard_log,
                  no_copy_or_start=True, ownership_unchanged=True, tracer_exercised=True,
                  host_alive=True, destroy_tx='tx_3')
    text += event('PASS', mode=mode, cycles=1, host_alive=True, retained_until_vm_shutdown=True)
    text += guard_log + control + 'Failed to apply overlay transaction 3: -16\n'
    text += f'MK_FW_PENDING mode={fault} hart=65537 actual=1 reported=3\n'
    return text


def recovery_log():
    text=''.join(line+'\n' for line in retention_log('lost-ack',0).splitlines()
                 if not line.startswith(('MK_LIFECYCLE_RETAINED','MK_LIFECYCLE_PASS','MK_FW_PENDING')))
    text += ('MK_CHILD_READY online=0-1 present=0-1 possible=0-3 boot=child2 release=test\n'
             'MK_CHILD_PONG\n')
    text += event('RECOVERED', boot='child2', host_alive=True,
                  trace=['mk_hsm_status: hart=65537 state=1', 'mk_hsm_status: hart=7 state=1',
                         'mk_copy:', 'mk_start:'])
    text += event('STOPPED', harts=[65537,7], host_alive=True,
                  hsm_trace=['mk_hsm_status: hart=65537 state=1','mk_hsm_status: hart=7 state=1'])
    return text+event('PASS',mode='lost-ack',cycles=1,host_alive=True)


class Retention(unittest.TestCase):
    def verify(self, text, mode='failed-retain', fault=8):
        return importlib.import_module('verify_retention').verify_retention(text, 0, mode, fault)

    def test_reachable_failed_state_and_lost_ack_retention(self):
        for mode, fault in (('failed-retain', 8), ('lost-ack', 7)):
            self.assertEqual(self.verify(retention_log(mode, fault), mode, fault)['result'], 'PASS')

    def test_missing_or_wrong_release_control_and_actual_release_rejected(self):
        text=retention_log()
        for before, after in (('kind=ring', 'kind=other'), ('phys=d0000000', 'phys=dead'),
                              ('"resources_after": {"image": 4096', '"resources_after": {"image": 8192'),
                              ('"tracer_exercised": true', '"tracer_exercised": false'),
                              ('"exec": {"error": 16', '"exec": {"error": 0'),
                              ('"positive_trace": ["mk_copy:", "mk_start:"]', '"positive_trace": []'),
                              ('"guard_log": "', '"guard_log": "MK_TEST_FREE id=1 kind=pool\\n'),
                              ('transaction 3: -16', 'transaction 3: -5')):
            with self.assertRaises(ValueError): self.verify(text.replace(before, after))

    def test_ack_loss_requires_real_matching_successful_ack_and_timeout(self):
        text=retention_log('lost-ack', 7)
        for before, after in (('request=3', 'request=0'), ('request=3', 'request=4'),
                              ('resource=1', 'resource=2'), ('operation=12290', 'operation=8193'),
                              ('"elapsed": 30.1', '"elapsed": 1.0'),
                              ('"error": 110', '"error": 16'),
                              ('Timeout waiting for operation 0x3002', 'Timeout waiting for operation 0x2001')):
            with self.assertRaises(ValueError): self.verify(text.replace(before, after), 'lost-ack', 7)

    def test_false_pass_duplicates_state_scope_and_diagnostics_rejected(self):
        text=retention_log()
        for broken in (text.replace('"state": "failed"', '"state": "active"'),
                       text.replace('MK_FW_PENDING mode=8', 'MK_FW_PENDING mode=7'),
                       text + event('PASS', mode='failed-retain', cycles=1, host_alive=True),
                       text + 'WARNING: bad\n', text + 'MK_CHILD_READY unexpected\n',
                       text + '[ 42.0] MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000\n'):
            with self.assertRaises(ValueError): self.verify(broken)

    def test_recovery_requires_latest_all_hart_stopped_before_copy(self):
        self.assertEqual(self.verify(recovery_log(),'lost-ack',0)['result'],'PASS')
        for before,after in (('"mk_copy:"','"mk_hsm_status: hart=7 state=0", "mk_copy:"'),
                             ('hart=7 state=1','hart=7 state=3'),
                             ('"boot": "child2"','"boot": "child"')):
            with self.assertRaises(ValueError): self.verify(recovery_log().replace(before,after),'lost-ack',0)


if __name__ == '__main__': unittest.main()
