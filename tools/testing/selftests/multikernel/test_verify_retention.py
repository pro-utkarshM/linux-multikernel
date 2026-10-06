# SPDX-License-Identifier: GPL-2.0-only
import importlib
import json
import unittest
from test_verify_lifecycle import event

R = dict(image=0x1000, ctrl=0xd0000000, manifest=0x9000, ring=0xa000,
         pool=0x2000, size=268435456, owned=2, tracked=2, ring_size=8192, manifest_size=4096)


def snapshot(state='failed'):
    phase = 'exec-rejected' if state == 'active' else 'confirm-exit'
    return ('[ 33.0] MK_TEST_RESOURCE id=1 phase=' + phase + ' state=' + state +
            ' image=1000 ctrl=d0000000 manifest=9000 ring=a000 pool=2000'
            ' size=268435456 owned=2 tracked=2 ring_size=8192 manifest_size=4096\n')


def retention_log(mode='failed-retain', fault=8):
    control = ('[ 1.0] MK_TEST_FREE id=1 kind=allocation phys=d0000000 size=4096 pool=2000\n'
               '[ 1.1] MK_TEST_FREE id=1 kind=allocation phys=d0200000 size=4096 pool=2000\n'
               '[ 1.2] MK_TEST_FREE id=1 kind=ring phys=a000 size=8192 pool=2000\n'
               '[ 1.3] MK_TEST_FREE id=1 kind=manifest phys=9000 size=4096 pool=2000\n'
               '[ 1.4] MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000\n')
    text = 'OpenSBI v1.8.1\n' + event('BEGIN', mode=mode, fault=fault, harts=[65537, 7],
                                      cycles=1, images='same', host_boot='host')
    text += 'kexec_file(Image): Loaded kernel at 0xd0200000 bufsz=0x1000 memsz=0x1000\n'
    text += event('CONTROL', resources=R, release_log=control, host_alive=True,
                  image_extent=[0xd0200000, 4096])
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
        text += 'MK_RETENTION_TRACE_BEGIN positive\nmk_copy:\nmk_start:\nMK_RETENTION_TRACE_END positive\n'
        if mode == 'panic-retain':
            text += ('MK_CHILD_ACTION mode=panic\nsysrq: Trigger a crash\n'
                     'Kernel panic - not syncing: sysrq triggered crash\nCall Trace:\n'
                     'Rebooting in 1 seconds..\n')
            text += event('PANIC', state='active', host_boot='host', timeout=1)
        else:
            text += event('TIMEOUT', error=110, state='active', elapsed=30.1,
                          ack=dict(type=12288, operation=12290, resource=1, request=3, result=0))
            text += ('[ 3.0] MK_TEST_ACK_DROPPED type=12288 operation=12290 resource=1 request=3 result=0\n'
                     '[ 33.0] Timeout waiting for operation 0x3002 on resource 1\n')
        state='active'
    guards = {name: dict(error=('failed' if name=='destroy' else 16),
                        trace=['mk_hsm_status: hart=65537 state=3'])
              for name in ('exec', 'unload', 'destroy')}
    guard_log = snapshot(state) + snapshot(state)
    extra = {}
    if state == 'active':
        expected = 3 if fault == 7 else 1
        guard_log = ''.join(snapshot(state) + ''.join(
            f'[ 34.0] MK_TEST_HSM id=1 phase=exec-rejected sample={sample} hart={hart} state={expected} error=0\n'
            for hart in (65537, 7)) for sample in (1, 2))
        guard_log += 'Failed to apply overlay transaction 3: -16\n'
        checks_trace = ['# entries-in-buffer/entries-written: 2/2   #P:2',
                        f'init-1 [000] 1.0: tracing_mark_write: MK_RETENTION_GUARD_BEGIN id=1 mode={mode} host_boot=host',
                        f'init-1 [000] 2.0: tracing_mark_write: MK_RETENTION_GUARD_END id=1 mode={mode} host_boot=host']
        for row in guards.values():
            row['trace'] = checks_trace
        extra = dict(host_boot='host', guard_trace=checks_trace,
                     trace_health=dict(enabled=dict(tracing_on='1', mk_copy='1', mk_start='1'),
                                       stats={f'cpu{i}': 'overrun: 0\ncommit overrun: 0\ndropped events: 0\n'
                                              for i in range(4)}),
                     observed_state='stop-pending' if fault == 7 else 'stopped')
        text += 'MK_RETENTION_TRACE_BEGIN guarded\n' + '\n'.join(checks_trace) + '\nMK_RETENTION_TRACE_END guarded\n'
    text += event('RETAINED', state=state, harts=[65537, 7], checks=guards,
                  positive_trace=['mk_copy:', 'mk_start:'],
                  resources_before=dict(R, tracked=0) if state == 'active' else R,
                  resources_after=R, guard_log=guard_log,
                  no_copy_or_start=True, ownership_unchanged=True, tracer_exercised=True,
                  host_alive=True, destroy_tx='tx_3', **extra)
    text += event('PASS', mode=mode, cycles=1, host_alive=True, host_boot='host',
                  retained_until_vm_shutdown=True)
    text += control
    if state == 'active':
        text += f'[ 33.9] MK_TEST_RETAIN_BEGIN id=1 mode={mode} host_boot=host\n'
        text += guard_log
        text += f'[ 34.1] MK_TEST_RETAIN_END id=1 mode={mode} host_boot=host\n'
    else:
        text += guard_log + 'Failed to apply overlay transaction 3: -16\n'
    if fault:
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
        for mode, fault in (('failed-retain', 8), ('lost-ack', 7), ('lost-ack', 0), ('panic-retain', 0)):
            self.assertEqual(self.verify(retention_log(mode, fault), mode, fault)['result'], 'PASS')

    def test_boot_pages_freed_after_pool_pointer_cleared(self):
        text=retention_log().replace('kind=ring phys=a000 size=8192 pool=2000',
                                    'kind=ring phys=a000 size=8192 pool=0').replace(
                                    'kind=manifest phys=9000 size=4096 pool=2000',
                                    'kind=manifest phys=9000 size=4096 pool=0')
        self.assertEqual(self.verify(text)['result'],'PASS')
        with self.assertRaises(ValueError): self.verify(text.replace('kind=ring phys=a000 size=8192',
                                                                    'kind=ring phys=a000 size=4096'))

    def test_duplicate_release_and_wrong_injection_scope_rejected(self):
        text=retention_log()
        pool='MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000'
        with self.assertRaises(ValueError): self.verify(text.replace(pool,pool+'\\n'+pool))
        for base,mode,fault in ((text,'failed-retain',8),(recovery_log(),'lost-ack',0)):
            with self.assertRaises(ValueError):
                self.verify(base+'MK_FW_PENDING mode=7 hart=7 actual=1 reported=3\n',mode,fault)

    def test_load_only_control_does_not_require_exec_time_control_block(self):
        text=retention_log()
        line=next(line for line in text.splitlines(keepends=True) if line.startswith('MK_LIFECYCLE_CONTROL'))
        control=json.loads(line.partition(' ')[2])
        control['resources']['ctrl']=0
        control['resources']['tracked']=0
        control['release_log']='\n'.join(row for row in control['release_log'].splitlines()
                                         if 'phys=d0000000' not in row)+'\n'
        changed=text.replace(line,event('CONTROL',**control)).replace(
            '[ 1.0] MK_TEST_FREE id=1 kind=allocation phys=d0000000 size=4096 pool=2000\n','')
        self.assertEqual(self.verify(changed)['result'],'PASS')

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

    def test_shared_release_control_requires_the_loaded_image_extent(self):
        text = retention_log()
        for before, after in (('phys=d0200000', 'phys=d0400000'),
                              ('memsz=0x1000', 'memsz=0x2000'),
                              ('"image_extent": [3491758080, 4096]', '"image_extent": []')):
            self.assertIn(before, text)
            with self.assertRaises(ValueError):
                self.verify(text.replace(before, after))

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

    def test_automatic_active_recovery_is_no_longer_accepted(self):
        with self.assertRaises(ValueError):
            self.verify(recovery_log(), 'lost-ack', 0)

    def test_retention_requires_fresh_complete_unique_hsm_groups(self):
        for mode, fault in (('lost-ack', 0), ('lost-ack', 7), ('panic-retain', 0)):
            text = retention_log(mode, fault)
            for old, new in (('sample=2 hart=7', 'sample=2 hart=65537'),
                             ('sample=2 hart=7', 'sample=2 hart=8'),
                             ('sample=2', 'sample=1'), ('error=0', 'error=-4'),
                             ('MK_TEST_HSM id=1', 'MK_TEST_HSM id=2'),
                             ('phase=exec-rejected sample=', 'phase=confirm-exit sample='),
                             ('MK_TEST_RETAIN_END id=1', 'MK_TEST_RETAIN_END id=2'),
                             ('host_boot=host', 'host_boot=other')):
                with self.subTest(mode=mode, mutation=old), self.assertRaises(ValueError):
                    self.verify(text.replace(old, new), mode, fault)
            missing = '\n'.join(row for row in text.splitlines()
                                if 'MK_TEST_HSM' not in row or row.startswith('MK_LIFECYCLE_'))+'\n'
            with self.assertRaises(ValueError): self.verify(missing, mode, fault)
            # Embedded claimed evidence cannot substitute for the raw dmesg window.
            with self.assertRaises(ValueError):
                self.verify(text.replace('[ 34.0] MK_TEST_HSM', '[ 34.0] STALE_HSM'), mode, fault)
            start = text.index('[ 33.9] MK_TEST_RETAIN_BEGIN')
            first = text.index('[ 34.0] MK_TEST_HSM', start)
            end = text.index('\n', first) + 1
            stale = text[:start] + text[first:end] + text[start:first] + text[end:]
            with self.assertRaises(ValueError): self.verify(stale, mode, fault)

    def test_latest_pending_or_error_never_proves_stopped(self):
        text = retention_log('lost-ack', 0)
        for old, new in (('sample=2 hart=7 state=1', 'sample=2 hart=7 state=3'),
                         ('sample=2 hart=7 state=1', 'sample=2 hart=7 state=0'),
                         ('error=0', 'error=-4')):
            with self.assertRaises(ValueError): self.verify(text.replace(old, new), 'lost-ack', 0)
        with self.assertRaises(ValueError):
            self.verify(retention_log('lost-ack', 7).replace('"stop-pending"', '"stopped"'), 'lost-ack', 7)

    def test_panic_requires_one_ordered_child_panic_and_timeout(self):
        text = retention_log('panic-retain', 0)
        for old, new in (('MK_CHILD_ACTION mode=panic', 'MK_CHILD_ACTION mode=reboot'),
                         ('Rebooting in 1 seconds', 'Rebooting in 0 seconds'),
                         ('sysrq triggered crash', 'unrelated failure'),
                         ('"timeout": 1', '"timeout": 0')):
            with self.assertRaises(ValueError): self.verify(text.replace(old, new), 'panic-retain', 0)
        for extra in ('Kernel panic - not syncing: sysrq triggered crash\n', 'Call Trace:\n'):
            with self.assertRaises(ValueError): self.verify(text + extra, 'panic-retain', 0)

    def test_retention_rejects_copy_start_free_and_unbound_trace(self):
        text = retention_log('lost-ack', 0)
        for extra in ('mk_copy:', 'mk_start:'):
            with self.assertRaises(ValueError):
                self.verify(text.replace('# entries-in-buffer', extra + ' # entries-in-buffer'), 'lost-ack', 0)
        with self.assertRaises(ValueError):
            self.verify(text.replace('MK_RETENTION_TRACE_BEGIN guarded', 'OLD_TRACE_BEGIN guarded'), 'lost-ack', 0)
        with self.assertRaises(ValueError):
            self.verify(text + 'MK_TEST_FREE id=1 kind=allocation phys=d0200000 size=4096 pool=2000\n', 'lost-ack', 0)

    def test_raw_traces_must_be_in_their_own_action_intervals(self):
        text = retention_log('lost-ack', 0)
        for phase in ('positive', 'guarded'):
            first = text.index(f'MK_RETENTION_TRACE_BEGIN {phase}\n')
            end_marker = f'MK_RETENTION_TRACE_END {phase}\n'
            last = text.index(end_marker) + len(end_marker)
            stale = text[first:last] + text[:first] + text[last:]
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                self.verify(stale, 'lost-ack', 0)

    def test_retention_never_skips_contradictory_resource_records(self):
        for mode, fault in (('failed-retain', 8), ('lost-ack', 0), ('panic-retain', 0)):
            text = retention_log(mode, fault)
            for bad in (snapshot('loaded'), snapshot('ready'), snapshot('active').replace('image=1000', 'image=0'),
                        snapshot('active').replace('owned=2', 'owned=0')):
                line = next(row for row in text.splitlines(True) if row.startswith('MK_LIFECYCLE_RETAINED'))
                data = json.loads(line.partition(' ')[2])
                old = data['guard_log']
                data['guard_log'] += bad
                changed = text.replace(line, event('RETAINED', **data)).replace(old, old + bad)
                with self.subTest(mode=mode, record=bad), self.assertRaises(ValueError):
                    self.verify(changed, mode, fault)

    def test_trace_loss_disabled_probe_or_missing_boundary_rejected(self):
        text = retention_log('lost-ack', 0)
        for old, new in (('2/2   #P:', '2/3   #P:'), ('overrun: 0', 'overrun: 1'),
                         ('dropped events: 0', 'dropped events: 1'), ('"mk_copy": "1"', '"mk_copy": "0"'),
                         ('"tracing_on": "1"', '"tracing_on": "0"'), ('"cpu3":', '"cpu4":'),
                         ('MK_RETENTION_GUARD_BEGIN', 'OLD_GUARD_BEGIN'),
                         ('MK_RETENTION_GUARD_END', 'OLD_GUARD_END')):
            with self.subTest(mutation=old), self.assertRaises(ValueError):
                self.verify(text.replace(old, new), 'lost-ack', 0)


if __name__ == '__main__': unittest.main()
