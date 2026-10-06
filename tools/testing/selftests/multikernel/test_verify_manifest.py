# SPDX-License-Identifier: GPL-2.0-only
"""Verifier fixtures are not native runtime evidence."""
import json
import unittest
from test_verify_lifecycle import complete_log, event
from test_verify_retention import R
from verify_manifest import verify_manifest


def manifest_log(mode='manifest-prepare'):
    fault, error = (1, 12) if mode == 'manifest-prepare' else (2, 28)
    rows = complete_log().replace('graceful', mode).splitlines(keepends=True)
    guard = (f'[ 1.0] MK_TEST_MANIFEST fault={fault} id=1\n'
             f'[ 1.1] Manifest finalization failed: -{error}; refusing start\n')
    rejected = event('MANIFEST_REJECTED', error=error, state='loaded',
                     ownership_unchanged=True, host_boot='host',
                     trace=['kerf: mk_hsm_status: hart=65537 state=1',
                            'kerf: mk_copy: kimage_load_segment'], guard_log=guard)
    recovered = event('MANIFEST_RECOVERED',
                      trace=['kerf: mk_hsm_status: hart=65537 state=1',
                             'kerf: mk_copy: kimage_load_segment',
                             'kerf: mk_start: sbi_hsm_hart_start'])
    release_log = ('MK_TEST_FREE id=1 kind=allocation phys=d0000000 size=8192 pool=2000\n'
                   'MK_TEST_FREE id=1 kind=allocation phys=90000000 size=2097152 pool=2000\n'
                   'MK_TEST_FREE id=1 kind=allocation phys=92000000 size=4096 pool=2000\n'
                   'MK_TEST_FREE id=1 kind=ring phys=a000 size=8192 pool=2000\n'
                   'MK_TEST_FREE id=1 kind=manifest phys=9000 size=4096 pool=2000\n'
                   'MK_TEST_FREE id=1 kind=pool phys=0 size=268435456 pool=2000\n')
    released = event('MANIFEST_RELEASED', resources=dict(R, owned=1), release_log=release_log,
                     image_extent=[0x90000000, 2097152])
    placement = 'kexec_file(Image): Loaded kernel at 0x90000000 bufsz=0x180000 memsz=0x200000\n'
    return (''.join(rows[:2]) + rejected + ''.join(rows[2:5]) + recovered +
            rows[5] + released + ''.join(rows[6:]) + placement + guard + release_log)


class ManifestVerification(unittest.TestCase):
    def test_real_failure_then_normal_lifecycle_is_required(self):
        for mode in ('manifest-prepare', 'manifest-capacity'):
            self.assertEqual(verify_manifest(manifest_log(mode), 0, mode, 1)['result'], 'PASS')

    def test_missing_wrong_or_unsafe_failure_is_rejected(self):
        text = manifest_log()
        for before, after in (
                ('"error": 12', '"error": 28'),
                ('"state": "loaded"', '"state": "failed"'),
                ('"host_boot": "host"', '"host_boot": "changed"'),
                ('"ownership_unchanged": true', '"ownership_unchanged": false'),
                ('fault=1 id=1', 'fault=2 id=1'),
                ('hart=65537 state=1', 'hart=65537 state=3'),
                ('kerf: mk_start:', 'kerf: missing_start:'),
                ('"kerf: mk_copy: kimage_load_segment"',
                 '"kerf: mk_copy: kimage_load_segment", "kerf: mk_start: unexpected"')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                changed = text.replace(before, after, 1) if 'host_boot' in before else text.replace(before, after)
                verify_manifest(changed, 0, 'manifest-prepare', 1)
        rows = text.splitlines(keepends=True)
        rejected = next(row for row in rows if row.startswith('MK_LIFECYCLE_MANIFEST_REJECTED'))
        for invalid in (text.replace(rejected, ''), text + rejected,
                        text.replace(rejected, '') + rejected,
                        text + 'MK_LIFECYCLE_FAIL {}\n'):
            with self.assertRaises(ValueError):
                verify_manifest(invalid, 0, 'manifest-prepare', 1)
        with self.assertRaises(ValueError):
            verify_manifest(text, 124, 'manifest-prepare', 1)

    def test_guard_log_must_match_actual_kernel_log_without_premature_free(self):
        text = manifest_log()
        with self.assertRaises(ValueError):
            verify_manifest(text.rsplit('[ 1.0] MK_TEST_MANIFEST', 1)[0],
                            0, 'manifest-prepare', 1)
        record = next(row for row in text.splitlines() if row.startswith('MK_LIFECYCLE_MANIFEST_REJECTED'))
        data = json.loads(record.partition(' ')[2])
        data['guard_log'] += 'MK_TEST_FREE id=1 kind=allocation\n'
        with self.assertRaises(ValueError):
            verify_manifest(text.replace(record + '\n', event('MANIFEST_REJECTED', **data)),
                            0, 'manifest-prepare', 1)

    def test_recovery_requires_actual_release_after_stopping(self):
        text = manifest_log()
        released = next(row for row in text.splitlines(keepends=True)
                        if row.startswith('MK_LIFECYCLE_MANIFEST_RELEASED'))
        for invalid in (text.replace(released, ''),
                        text.replace(released, '').replace('MK_LIFECYCLE_STOPPED',
                                                          released + 'MK_LIFECYCLE_STOPPED'),
                        text.replace('phys=d0000000', 'phys=d0001000'),
                        text.replace('kind=pool', 'kind=unknown')):
            with self.assertRaises(ValueError):
                verify_manifest(invalid, 0, 'manifest-prepare', 1)

    def test_stopped_evidence_must_precede_the_first_copy(self):
        text = manifest_log()
        before = '"kerf: mk_hsm_status: hart=65537 state=1", "kerf: mk_copy: kimage_load_segment"'
        after = '"kerf: mk_copy: kimage_load_segment", "kerf: mk_hsm_status: hart=65537 state=1"'
        self.assertIn(before, text)
        with self.assertRaises(ValueError):
            verify_manifest(text.replace(before, after), 0, 'manifest-prepare', 1)

    def test_image_release_cannot_be_replaced_by_initrd_release(self):
        text = manifest_log()
        image_free = 'MK_TEST_FREE id=1 kind=allocation phys=90000000 size=2097152 pool=2000'
        invalid = text.replace(image_free + '\\n', '').replace(image_free + '\n', '')
        with self.assertRaises(ValueError):
            verify_manifest(invalid, 0, 'manifest-prepare', 1)
        for before, after in (('memsz=0x200000', 'memsz=0x400000'),
                              ('Loaded kernel at 0x90000000', 'Loaded kernel at 0x90200000')):
            with self.assertRaises(ValueError):
                verify_manifest(text.replace(before, after), 0, 'manifest-prepare', 1)

    def test_latest_status_in_each_window_and_recovery_start_order(self):
        text = manifest_log()
        for phase in ('MANIFEST_REJECTED', 'MANIFEST_RECOVERED'):
            row = next(line for line in text.splitlines(keepends=True)
                       if line.startswith('MK_LIFECYCLE_' + phase))
            record = json.loads(row.partition(' ')[2])
            broken = dict(record, trace=[record['trace'][0],
                                        'kerf: mk_hsm_status: hart=65537 state=3'] +
                                       record['trace'][1:])
            with self.assertRaises(ValueError):
                verify_manifest(text.replace(row, event(phase, **broken)), 0, 'manifest-prepare', 1)
            if phase == 'MANIFEST_RECOVERED':
                for trace in (record['trace'][1:], list(reversed(record['trace']))):
                    with self.assertRaises(ValueError):
                        verify_manifest(text.replace(row, event(phase, **dict(record, trace=trace))),
                                        0, 'manifest-prepare', 1)


if __name__ == '__main__':
    unittest.main()
