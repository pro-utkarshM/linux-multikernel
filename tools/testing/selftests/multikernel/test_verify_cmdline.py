# SPDX-License-Identifier: GPL-2.0-only
"""An errno must not substitute for an observed allocation/free lifetime."""
import copy
import importlib.util
from pathlib import Path
import unittest
from test_verify_lifecycle import complete_log, event


def record(control=False):
    phase = 'control' if control else 'rejected'
    events = [f'tracing_mark_write: MK_CMDLINE_BEGIN {phase} host',
              'kmalloc: call_site=memdup_user+0x10 ptr=ffff800000001000 bytes_req=16 bytes_alloc=32',
              'mk_cmdline_alloc: (memdup_user) ptr=0xffff800000001000 length=16']
    if control:
        events += ['tracing_mark_write: MK_CMDLINE_LOADED control host',
                   'tracing_mark_write: MK_CMDLINE_UNLOAD control host']
    events += ['kfree: call_site=kimage_file_free_cmdline+0x10 ptr=ffff800000001000',
               f'tracing_mark_write: MK_CMDLINE_END {phase} host']
    trace = '# entries-in-buffer/entries-written: 7/7   #P:4\n'
    trace += ''.join('init-1 [000] 1.000: ' + event + '\n' for event in events)
    return dict(phase=phase, host_boot='host', command='123456789012345' if control else '1234567890123456',
                length=16, error=0 if control else 22, state='ready',
                ownership_unchanged=True, kimage='MK_ID Type Start Address Segments Mode Cmdline\n-----\n',
                loaded_state='loaded' if control else None,
                loaded_kimage=('MK_ID Type Start Address Segments Mode Cmdline\n-----\n'
                               '1 multikernel 0x90000000 2 file "123456789012345"\n') if control else None,
                trace=trace,
                health=dict(enabled={'tracing_on': '0', 'alloc': '1', 'kmalloc': '1', 'kfree': '1'},
                            filters={key: 'common_pid == 1' for key in ('alloc', 'kmalloc', 'kfree')},
                            profile='mk_cmdline_alloc 2 0\n',
                            stats={f'cpu{i}': 'overrun: 0\ncommit overrun: 0\ndropped events: 0\n'
                                   for i in range(4)}))


class CmdlineVerification(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name('verify_cmdline.py')
        self.assertTrue(path.exists(), 'command-line lifetime verifier not implemented')
        spec = importlib.util.spec_from_file_location('verify_cmdline', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.verify = module.verify_record
        self.verify_full = module.verify_cmdline

    def test_requires_actual_allocator_free_and_successful_retention(self):
        for control in (False, True):
            self.assertEqual(self.verify(record(control)), 0xffff800000001000)

    def test_missing_duplicate_wrong_pointer_or_early_free_fails(self):
        for control in (False, True):
            original = record(control)
            freed = 'init-1 [000] 1.000: kfree: call_site=kimage_file_free_cmdline+0x10 ptr=ffff800000001000\n'
            for change in (lambda t: t.replace(freed, ''),
                           lambda t: t.replace(freed, freed * 2),
                           lambda t: t.replace('ptr=ffff800000001000\n', 'ptr=ffff800000002000\n'),
                           lambda t: t.replace('bytes_req=16', 'bytes_req=8'),
                           lambda t: t.replace('length=16', 'length=8'),
                           lambda t: t.replace('ptr=ffff800000001000', 'ptr=0000000012345678')):
                bad = copy.deepcopy(original)
                bad['trace'] = change(bad['trace'])
                with self.assertRaises(ValueError):
                    self.verify(bad)
        bad = record(True)
        bad['trace'] = bad['trace'].replace(freed, '')
        bad['trace'] = bad['trace'].replace('init-1 [000] 1.000: tracing_mark_write: MK_CMDLINE_LOADED',
                                           freed + 'init-1 [000] 1.000: tracing_mark_write: MK_CMDLINE_LOADED')
        with self.assertRaises(ValueError):
            self.verify(bad)

    def test_allocator_address_reuse_is_not_double_free(self):
        value = record()
        reuse = ('init-1 [000] 1.000: kmalloc: ptr=ffff800000001000 bytes_req=8\n'
                 'init-1 [000] 1.000: kfree: ptr=ffff800000001000\n')
        value['trace'] = value['trace'].replace('init-1 [000] 1.000: tracing_mark_write: MK_CMDLINE_END',
                                               reuse + 'init-1 [000] 1.000: tracing_mark_write: MK_CMDLINE_END')
        self.assertEqual(self.verify(value), 0xffff800000001000)

    def test_missing_lost_or_disabled_trace_cannot_pass(self):
        for field in ('overrun', 'commit overrun', 'dropped events'):
            bad = record()
            bad['health']['stats']['cpu0'] = bad['health']['stats']['cpu0'].replace(field + ': 0', field + ': 1')
            with self.assertRaises(ValueError):
                self.verify(bad)
        for key, value in (('profile', 'mk_cmdline_alloc 2 1\n'), ('stats', {}),
                           ('enabled', {}), ('filters', {})):
            bad = record()
            bad['health'][key] = value
            with self.assertRaises(ValueError):
                self.verify(bad)
        for before, after in (('7/7', '6/7'), ('MK_CMDLINE_BEGIN', 'MISSING'),
                              ('rejected host', 'rejected other')):
            bad = record()
            bad['trace'] = bad['trace'].replace(before, after)
            with self.assertRaises(ValueError):
                self.verify(bad)

    def test_published_failure_missing_retained_command_and_wrong_scope_fail(self):
        for key, value in (('error', 12), ('state', 'loaded'), ('ownership_unchanged', False),
                           ('kimage', record(True)['loaded_kimage'])):
            bad = record()
            bad[key] = value
            with self.assertRaises(ValueError):
                self.verify(bad)
        bad = record(True)
        bad['loaded_kimage'] = bad['kimage']
        with self.assertRaises(ValueError):
            self.verify(bad)

    def test_cleanup_must_precede_real_recovery_and_exit_success(self):
        rows = complete_log().replace('graceful', 'cmdline-cleanup').splitlines(keepends=True)
        observations = event('CMDLINE', **record()) + event('CMDLINE', **record(True))
        text = ''.join(rows[:2]) + observations + ''.join(rows[2:])
        self.assertEqual(self.verify_full(text, 0, 1)['result'], 'PASS')
        for bad in (text.replace(observations, ''), text + observations,
                    ''.join(rows) + observations,
                    text.replace('MK_CHILD_PONG', 'MISSING'),
                    text.replace('"host_boot": "host", "command"', '"host_boot": "other", "command"')):
            with self.assertRaises(ValueError):
                self.verify_full(bad, 0, 1)
        with self.assertRaises(ValueError):
            self.verify_full(text, 124, 1)

    def test_guest_observer_refuses_non_guest_before_side_effects(self):
        import cmdline_trace
        with self.assertRaisesRegex(RuntimeError, 'disposable RISC-V guest PID1'):
            cmdline_trace.run(None, None, None, None, None, None)


if __name__ == '__main__':
    unittest.main()
