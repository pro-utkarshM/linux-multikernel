# SPDX-License-Identifier: GPL-2.0-only
import json
import unittest
from verify_lifecycle import verify


def event(kind, **values):
    return 'MK_LIFECYCLE_' + kind + ' ' + json.dumps(values) + '\n'


def complete_log():
    return ('OpenSBI v1.8.1\n' +
            event('BEGIN', mode='graceful', harts=[65537], cycles=1, host_boot='host', images='same') +
            'MK_CHILD_READY online=0 present=0 possible=0-3 boot=child release=linux-test\n' +
            'MK_CHILD_PONG\n' +
            event('CHILD', cycle=1, boot='child', assigned=[65537], online=[0],
                  ring_roundtrip=True, release='linux-test', image_sha='a' * 64,
                  image_start=0x90000000, active_unload_rejected=True) +
            event('STOPPED', cycle=1, harts=[65537], host_alive=True,
                  hsm_trace=['kerf-1 [000] 1.000: mk_hsm_status: hart=65537 state=1']) +
            event('PASS', mode='graceful', cycles=1, host_alive=True))


class Verification(unittest.TestCase):
    def test_writer_stress_requires_real_roundtrips_and_overlapping_workers(self):
        text = complete_log().replace('graceful', 'writer-stress')
        stop = next(line for line in text.splitlines(keepends=True)
                    if line.startswith('MK_LIFECYCLE_STOPPED'))
        stress = ''.join('MK_CHILD_PONG token=round-%d\n' % i for i in range(64))
        stress += event('STRESS', cycle=1, unload_rejections=64,
                        console_roundtrips=64, console_closes=64, closing_sends=64,
                        worker_windows=[[100, 400], [200, 500]],
                        incoming_workers_exercised=False, force_stop_error=95)
        text = text.replace(stop, stress + stop)
        self.assertEqual(verify(text, 0, 'writer-stress', 1, 1)['result'], 'PASS')
        for before, after in (('token=round-17\n', 'token=round-16\n'),
                              ('"unload_rejections": 64', '"unload_rejections": 0'),
                              ('"console_closes": 64', '"console_closes": 63'),
                              ('"force_stop_error": 95', '"force_stop_error": 0'),
                              ('[200, 500]', '[401, 500]'),
                              ('"incoming_workers_exercised": false',
                               '"incoming_workers_exercised": true')):
            with self.assertRaises(ValueError):
                verify(text.replace(before, after), 0, 'writer-stress', 1, 1)

    def test_alternating_images_require_distinct_execution_and_fixed_address(self):
        rows = complete_log().splitlines(keepends=True)
        begin = json.loads(rows[1].partition(' ')[2])
        begin.update(cycles=2, images='alternate')
        first = ''.join(rows[2:-1])
        second = first.replace('child', 'child2').replace('"cycle": 1', '"cycle": 2')
        second = second.replace('a' * 64, 'b' * 64).replace('linux-test', 'linux-alt')
        text = (rows[0] + event('BEGIN', **begin) + first + second +
                event('PASS', mode='graceful', cycles=2, host_alive=True))
        self.assertEqual(verify(text, 0, 'graceful', 1, 2, 'alternate')['result'], 'PASS')
        for before, after in (('b' * 64, 'a' * 64), ('linux-alt', 'linux-test'),
                              ('"image_start": 2415919104', '"image_start": 2418016256')):
            broken = text.replace(before, after) if before != '"image_start": 2415919104' else \
                text[:text.index(second)] + second.replace(before, after) + text[text.index(second) + len(second):]
            with self.assertRaises(ValueError):
                verify(broken, 0, 'graceful', 1, 2, 'alternate')

    def test_fixed_image_address_and_valid_hash_are_required(self):
        for before, after in (('"image_start": 2415919104', '"image_start": 2415919105'),
                              ('"image_sha": "' + 'a' * 64 + '"', '"image_sha": ""')):
            with self.assertRaises(ValueError):
                verify(complete_log().replace(before, after), 0, 'graceful', 1, 1)
        with self.assertRaises(ValueError):
            verify(complete_log().replace('"active_unload_rejected": true', '"active_unload_rejected": false'),
                   0, 'graceful', 1, 1)

    def test_raw_hsm_stop_evidence_is_required(self):
        text = complete_log()
        for before, after in (('hart=65537 state=1', 'hart=65537 state=3'),
                              ('hart=65537 state=1', 'hart=7 state=1'),
                              ('hart=65537 state=1', '')):
            with self.assertRaises(ValueError):
                verify(text.replace(before, after), 0, 'graceful', 1, 1)

    def test_complete_native_evidence(self):
        self.assertEqual(verify(complete_log(), 0, 'graceful', 1, 1)['result'], 'PASS')

    def test_latest_stop_and_raw_child_identity_must_match(self):
        text = complete_log()
        row = next(line for line in text.splitlines(keepends=True)
                   if line.startswith('MK_LIFECYCLE_STOPPED '))
        stopped = json.loads(row.partition(' ')[2])
        stopped['hsm_trace'].append('kerf: mk_hsm_status: hart=65537 state=3')
        for invalid in (text.replace(row, event('STOPPED', **stopped)),
                        text.replace('boot=child', 'boot=host'),
                        text.replace('release=linux-test', 'release=wrong-linux')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                verify(invalid, 0, 'graceful', 1, 1)

    def test_expected_panic_stack_requires_timeout_and_host_survival(self):
        text = complete_log().replace('graceful', 'panic')
        panic = 'MK_CHILD_ACTION mode=panic\nsysrq: Trigger a crash\nKernel panic - not syncing: sysrq\nCall Trace:\nRebooting in 1 seconds..\n'
        stop = next(line for line in text.splitlines(keepends=True) if line.startswith('MK_LIFECYCLE_STOPPED'))
        text = text.replace(stop, panic + stop)
        # Reusable panic settlement is intentionally no longer qualified here.
        with self.assertRaises(ValueError):
            verify(text, 0, 'panic', 1, 1)
        with self.assertRaises(ValueError):
            verify(text.replace('Rebooting in 1 seconds..', ''), 0, 'panic', 1, 1)
        with self.assertRaises(ValueError):
            verify(text.replace(panic, '') + panic, 0, 'panic', 1, 1)
        with self.assertRaises(ValueError):
            verify(panic + text.replace(panic, ''), 0, 'panic', 1, 1)

    def test_timeout_or_failure_after_pass(self):
        for text, code in ((complete_log(), 124),
                           (complete_log() + event('FAIL', error='late'), 0),
                           (complete_log() + 'WARNING: CPU: 0\n', 0)):
            with self.assertRaises(ValueError):
                verify(text, code, 'graceful', 1, 1)

    def test_missing_out_of_order_or_duplicate_stop(self):
        rows = complete_log().splitlines(keepends=True)
        stopped = rows[-2]
        for text in (complete_log().replace(stopped, ''),
                     complete_log().replace(stopped, stopped + stopped),
                     ''.join(rows[:-3] + [rows[-2], rows[-3], rows[-1]])):
            with self.assertRaises(ValueError):
                verify(text, 0, 'graceful', 1, 1)

    def test_no_child_execution_or_roundtrip(self):
        for field in ('MK_CHILD_READY', 'MK_CHILD_PONG', 'OpenSBI'):
            text = '\n'.join(line for line in complete_log().splitlines() if field not in line)
            with self.assertRaises(ValueError):
                verify(text, 0, 'graceful', 1, 1)

    def test_wrong_scope_and_reclaimed_before_stop(self):
        for before, after in (('"ring_roundtrip": true', '"ring_roundtrip": false'),
                              ('"host_alive": true', '"host_alive": false'),
                              ('"assigned": [65537]', '"assigned": [7]'),
                              ('"harts": [65537]', '"harts": []')):
            with self.assertRaises(ValueError):
                verify(complete_log().replace(before, after), 0, 'graceful', 1, 1)
        with self.assertRaises(ValueError):
            verify(complete_log(), 0, 'reboot', 1, 1)


if __name__ == '__main__':
    unittest.main()
