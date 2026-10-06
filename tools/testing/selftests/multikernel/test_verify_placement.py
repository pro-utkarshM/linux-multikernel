# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic verifier fixtures only; never QEMU/runtime evidence."""
import json
from pathlib import Path
import subprocess
import unittest
from test_verify_lifecycle import event
from test_verify_retention import R, snapshot
from verify_placement import verify_placement


INJECTION = '[ 1.0] MK_TEST_PLACEMENT id=1 original=0x90000000 injected=0x90001000 size=2097152 align=0x200000\n'
REJECTION = '[ 1.1] Multikernel allocation not aligned: phys=0x90001000, required=0x200000\n'
FREE = '[ 1.2] MK_TEST_FREE id=1 kind=allocation phys=90000000 size=2097152 pool=2000\n'
GUARD = INJECTION + REJECTION + FREE


def trace_block(phase, lines):
    return (f'MK_PLACEMENT_TRACE_BEGIN {phase}\n' + '\n'.join(lines) + '\n' +
            f'MK_PLACEMENT_TRACE_END {phase}\n')


def placement_log(harts=1, guard=GUARD, before=None, after=None):
    ids = [65537, 7][:harts]
    before = ['# tracer: nop'] if before is None else before
    online = '0-1' if harts == 2 else '0'
    after = ([f'kerf-1 [000] 2.000: mk_hsm_status: hart={hart} state=1' for hart in ids] +
             ['kerf-1 [000] 2.001: mk_copy: kimage_load_segment',
              'kerf-1 [000] 2.002: mk_start: sbi_hsm_hart_start']) if after is None else after
    after = ['# tracer: nop', 'kerf: mk_copy: load-time segment',
             'init: tracing_mark_write: MK_PLACEMENT_EXEC'] + after
    release = ('[ 4.0] MK_TEST_FREE id=1 kind=allocation phys=d0000000 size=8192 pool=2000\n'
               '[ 4.1] MK_TEST_FREE id=1 kind=allocation phys=90000000 size=2097152 pool=2000\n'
               '[ 4.2] MK_TEST_FREE id=1 kind=allocation phys=92000000 size=4096 pool=2000\n'
               '[ 4.3] MK_TEST_FREE id=1 kind=ring phys=a000 size=8192 pool=0\n'
               '[ 4.4] MK_TEST_FREE id=1 kind=manifest phys=9000 size=4096 pool=0\n'
               '[ 4.5] MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000\n')
    return ('OpenSBI v1.8.1\n' +
            event('BEGIN', mode='placement-negative', harts=ids, cycles=1,
                  host_boot='host', images='same', fault=0) +
            trace_block('rejected', before) +
            event('PLACEMENT_REJECTED', error=12, state='ready', ownership_unchanged=True,
                  host_boot='host', trace=before, guard_log=guard) +
            f'MK_CHILD_READY online={online} present={online} possible=0-3 boot=child release=linux-test\n' +
            'MK_CHILD_PONG\n' +
            event('CHILD', cycle=1, boot='child', assigned=ids, online=list(range(harts)),
                  ring_roundtrip=True, release='linux-test', image_sha='a' * 64,
                  image_start=0x90000000, active_unload_rejected=True) +
            trace_block('recovered', after) + event('PLACEMENT_RECOVERED', trace=after) +
            event('STOPPED', cycle=1, harts=ids, host_alive=True,
                  hsm_trace=[f'kerf-1 [000] 3.000: mk_hsm_status: hart={hart} state=1' for hart in ids]) +
            event('PLACEMENT_RELEASED', resources=dict(R, owned=harts), release_log=release,
                  image_extent=[0x90000000, 2097152]) +
            event('PASS', mode='placement-negative', cycles=1, host_alive=True) + guard +
            'kexec_file(Image): Loaded kernel at 0x90000000 bufsz=0x180000 memsz=0x200000\n' +
            snapshot('loaded').replace('owned=2', f'owned={harts}') + release)


def change_record(text, phase, **changes):
    row = next(row for row in text.splitlines(keepends=True)
               if row.startswith('MK_LIFECYCLE_' + phase + ' '))
    record = json.loads(row.partition(' ')[2])
    return text.replace(row, event(phase, **dict(record, **changes)))


class PlacementVerification(unittest.TestCase):
    def verify(self, text, harts=1, status=0):
        return verify_placement(text, status, harts)

    def test_rejection_free_and_real_recovery_are_required(self):
        for harts in (1, 2):
            with self.subTest(harts=harts):
                result = self.verify(placement_log(harts), harts)
                self.assertEqual(result['result'], 'PASS')
                self.assertEqual(result['mode'], 'placement-negative')
                self.assertNotIn('manifest_fault', result)

    def test_bad_free_or_injection_cannot_pass(self):
        for guard in (INJECTION + REJECTION, GUARD + FREE,
                      GUARD.replace(FREE, FREE.replace('phys=90000000', 'phys=90001000')),
                      GUARD.replace(FREE, FREE.replace('size=2097152', 'size=4096')),
                      GUARD.replace(FREE, FREE.replace('pool=2000', 'pool=3000')),
                      GUARD.replace('injected=0x90001000', 'injected=0x90002000'),
                      GUARD.replace('original=0x90000000', 'original=0x90001000'),
                      GUARD.replace('align=0x200000', 'align=0x1000'),
                      GUARD.replace('required=0x200000', 'required=0x1000'),
                      GUARD.replace(REJECTION, ''), INJECTION + GUARD,
                      FREE + INJECTION + REJECTION, REJECTION + INJECTION + FREE):
            with self.subTest(guard=guard), self.assertRaises(ValueError):
                self.verify(placement_log(guard=guard))

    def test_copy_start_and_latest_stopped_order(self):
        for event_name in ('mk_copy:', 'mk_start:'):
            with self.subTest(event_name=event_name), self.assertRaises(ValueError):
                self.verify(placement_log(before=['# tracer: nop', 'kerf: ' + event_name]))
        stopped = 'kerf: mk_hsm_status: hart=65537 state=1'
        for after in ([stopped, 'kerf: mk_copy:'], [stopped, 'kerf: mk_start:'],
                      ['kerf: mk_copy:', stopped, 'kerf: mk_start:'],
                      [stopped, 'kerf: mk_start:', 'kerf: mk_copy:'],
                      [stopped, 'kerf: mk_hsm_status: hart=65537 state=3',
                       'kerf: mk_copy:', 'kerf: mk_start:']):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.verify(placement_log(after=after))
        with self.assertRaises(ValueError):
            self.verify(placement_log(2).replace('hart=7 state=1', 'hart=9 state=1'), 2)

    def test_json_cannot_substitute_for_actual_logs(self):
        text = placement_log()
        before = trace_block('rejected', ['# tracer: nop'])
        start = text.index('MK_PLACEMENT_TRACE_BEGIN recovered\n')
        end = text.index('MK_PLACEMENT_TRACE_END recovered\n') + len('MK_PLACEMENT_TRACE_END recovered\n')
        for invalid in (text.replace(GUARD, ''), text.replace(before, ''),
                        text[:start] + text[end:], text + GUARD,
                        text.replace(FREE, ''), text + FREE,
                        text.replace('[ 4.1] MK_TEST_FREE id=1 kind=allocation phys=90000000 size=2097152 pool=2000\n', ''),
                        change_record(text, 'PLACEMENT_REJECTED', trace=[]),
                        change_record(text, 'PLACEMENT_RECOVERED', trace=['mk_copy:', 'mk_start:'])):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.verify(invalid)

    def test_missing_recovery_release_or_wrong_scope_is_rejected(self):
        text = placement_log()
        for phase in ('PLACEMENT_REJECTED', 'PLACEMENT_RECOVERED', 'PLACEMENT_RELEASED', 'STOPPED'):
            row = next(row for row in text.splitlines(keepends=True)
                       if row.startswith('MK_LIFECYCLE_' + phase + ' '))
            for invalid in (text.replace(row, ''), text + row, text.replace(row, '') + row):
                with self.subTest(phase=phase), self.assertRaises(ValueError):
                    self.verify(invalid)
        for phase, changes in (
                ('BEGIN', dict(fault=1)), ('BEGIN', dict(cycles=2)), ('BEGIN', dict(images='alternate')),
                ('PLACEMENT_REJECTED', dict(error=22)), ('PLACEMENT_REJECTED', dict(state='loaded')),
                ('PLACEMENT_REJECTED', dict(ownership_unchanged=False)),
                ('PLACEMENT_REJECTED', dict(host_boot='changed'))):
            with self.subTest(phase=phase, changes=changes), self.assertRaises(ValueError):
                self.verify(change_record(text, phase, **changes))
        for before, after in (('MK_CHILD_READY ', 'missing_ready '), ('MK_CHILD_PONG', 'missing_pong'),
                              ('memsz=0x200000', 'memsz=0x400000'),
                              ('Loaded kernel at 0x90000000', 'Loaded kernel at 0x90200000'),
                              ('kind=pool', 'kind=unknown')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.verify(text.replace(before, after))
        for invalid in (text + 'MK_LIFECYCLE_FAIL {}\n', text + 'WARNING: broken\n',
                        text + 'MK_TEST_MANIFEST fault=1 id=1\n'):
            with self.assertRaises(ValueError):
                self.verify(invalid)
        with self.assertRaises(ValueError):
            self.verify(text, status=124)

    def test_injected_pointer_cannot_be_freed_during_later_cleanup(self):
        for invalid in (placement_log().replace('phys=92000000', 'phys=90001000'),
                        placement_log() + 'MK_TEST_FREE id=2 kind=allocation phys=90001000 size=4096 pool=2000\n'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.verify(invalid)

    def test_free_must_precede_retry_in_actual_dmesg(self):
        text = placement_log()
        with self.assertRaises(ValueError):
            self.verify(text.replace(GUARD, '') + GUARD)

    def test_load_and_exec_windows_need_an_explicit_boundary(self):
        marker = 'init: tracing_mark_write: MK_PLACEMENT_EXEC'
        for invalid in (placement_log().replace(marker, 'missing-boundary'),
                        placement_log(after=[marker, 'kerf: mk_copy:', 'kerf: mk_start:']),
                        placement_log().replace('kerf: mk_copy: load-time segment',
                                                'kerf: mk_start: unexpected load start')):
            with self.assertRaises(ValueError):
                self.verify(invalid)

    def test_final_stop_cannot_be_superseded_before_release(self):
        trace = ['kerf: mk_hsm_status: hart=65537 state=1',
                 'kerf: mk_hsm_status: hart=65537 state=3']
        with self.assertRaises(ValueError):
            self.verify(change_record(placement_log(), 'STOPPED', hsm_trace=trace))

    def test_runner_rejects_expanded_scope_before_staging(self):
        runner = str(Path(__file__).with_name('qemu_lifecycle_test.sh'))
        for harts, cycles, alternate, fault in (('3', '1', '', '0'), ('1', '2', '', '0'),
                                               ('2', '1', 'alternate', '0'), ('1', '1', '', '1')):
            with self.subTest(harts=harts, cycles=cycles, alternate=alternate, fault=fault):
                result = subprocess.run(['bash', runner] + ['/nonexistent-placement-test'] * 6 +
                                        ['placement-negative', harts, cycles, alternate, fault],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout + result.stderr, '')


if __name__ == '__main__':
    unittest.main()
