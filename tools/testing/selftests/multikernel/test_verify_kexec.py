# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic log checks only; these do not execute kexec or qualify a VM."""
import json
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from verify_kexec import verify_artifacts, verify_kexec

TOKEN = '0123456789abcdef0123456789abcdef'
SHA = 'a' * 64
RELEASE = 'linux-test'


def event(kind, **values):
    return 'MK_KEXEC_' + kind + ' ' + json.dumps(values) + '\n'


def log(mode='ordinary'):
    crash = mode == 'crash'
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                         4, 243, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0).hex()
    return ('OpenSBI v1.8.1\nLinux version linux-test (builder)\n' +
            event('BEGIN', mode=mode, token=TOKEN, boot='host', release=RELEASE,
                  online='0-3', image_sha=SHA, loaded=0, crash_loaded=0,
                  crash_size=268435456 if crash else 0) +
            'kexec_file(Image): Loaded kernel at 0x90000000 bufsz=0x180000 memsz=0x200000\n' +
            f'kexec_file_load: type:{1 if crash else 0}, start:0x9ffff000 head:0x8000 flags:0x{10 if crash else 8:x}\n' +
            event('LOADED', mode=mode, token=TOKEN, flags=10 if crash else 8,
                  loaded=0 if crash else 1, crash_loaded=1 if crash else 0) +
            event('HANDOFF', mode=mode, token=TOKEN, boot='host',
                  action='sysrq-c' if crash else 'reboot-kexec') +
            ('sysrq: Trigger a crash\nKernel panic - not syncing: sysrq triggered crash\n'
             'Call Trace:\nStarting crashdump kernel...\n' if crash else '') +
            'Will call new kernel at 9ffff000 from hart id 0\nBye...\n' +
            'Linux version linux-test (builder)\n' +
            event('TARGET', mode=mode, token=TOKEN, boot='target', release=RELEASE,
                  online='0' if crash else '0-3', vmcore_size=1073741824 if crash else 0,
                  vmcore_header=header if crash else '-') +
            event('PASS', mode=mode, token=TOKEN, boot='target') + 'reboot: Power down\n')


def change(text, kind, **values):
    line = next(line for line in text.splitlines(keepends=True)
                if line.startswith('MK_KEXEC_' + kind + ' '))
    data = json.loads(line.partition(' ')[2])
    return text.replace(line, event(kind, **dict(data, **values)))


class KexecVerification(unittest.TestCase):
    def test_frozen_artifacts_need_the_selected_builds_exact_hash_entries(self):
        verify = verify_artifacts
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build, bundle = root / 'build', root / 'bundle'
            bundle.mkdir()
            pairs = (('arch/riscv/boot/Image', 'Image'),
                     ('vmlinux.unstripped', 'vmlinux.unstripped'), ('.config', 'kernel.config'))
            lines = []
            for source, frozen in pairs:
                data = frozen.encode()
                (bundle / frozen).write_bytes(data)
                lines.append(hashlib.sha256(data).hexdigest() + '  build/' + source + '\n')
            manifest = bundle / 'build-artifacts.sha256'
            manifest.write_text(''.join(lines))
            verify(root, build, bundle)
            for invalid in (lines[2], ''.join(lines).replace('build/', 'another-build/'),
                            ''.join(lines + [lines[0]])):
                manifest.write_text(invalid)
                with self.assertRaises(ValueError):
                    verify(root, build, bundle)
            manifest.write_text(''.join(lines))
            (bundle / 'Image').write_bytes(b'wrong Image')
            with self.assertRaises(ValueError):
                verify(root, build, bundle)

    def verify(self, text, mode='ordinary', status=0):
        return verify_kexec(text, status, mode, TOKEN, RELEASE, SHA)

    def test_both_actual_handoffs_are_required(self):
        for mode in ('ordinary', 'crash'):
            self.assertEqual(self.verify(log(mode), mode)['result'], 'PASS')

    def test_missing_duplicate_and_reordered_stages(self):
        text = log()
        for kind in ('BEGIN', 'LOADED', 'HANDOFF', 'TARGET', 'PASS'):
            row = next(row for row in text.splitlines(keepends=True)
                       if row.startswith('MK_KEXEC_' + kind + ' '))
            for bad in (text.replace(row, ''), text + row, row + text.replace(row, '')):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    self.verify(bad)

    def test_identity_flags_and_scope_cannot_self_certify(self):
        text = log()
        for kind, values in (
                ('BEGIN', dict(token='b' * 32)), ('BEGIN', dict(image_sha='b' * 64)),
                ('BEGIN', dict(online='0')), ('BEGIN', dict(crash_size=268435456)),
                ('LOADED', dict(flags=16)), ('LOADED', dict(loaded=0)),
                ('LOADED', dict(crash_loaded=1)), ('HANDOFF', dict(action='poweroff')),
                ('HANDOFF', dict(boot='different')), ('TARGET', dict(boot='host')),
                ('TARGET', dict(release='wrong')), ('TARGET', dict(online='0')),
                ('PASS', dict(boot='wrong')), ('PASS', dict(token='b' * 32))):
            with self.subTest(kind=kind, values=values), self.assertRaises(ValueError):
                self.verify(change(text, kind, **values))
        with self.assertRaises(ValueError):
            self.verify(text.replace(TOKEN, 'b' * 32))

    def test_raw_execution_and_error_windows(self):
        text = log()
        for before, after in (('OpenSBI v1.8.1', ''), ('Bye...', 'WARNING: broken'),
                              ('Will call new kernel at 9ffff000', 'Will call new kernel at 9fffe000'),
                              ('type:0, start:', 'type:2, start:'), ('flags:0x8', 'flags:0x18'),
                              ('kexec_file_load: type:', 'missing: type:'),
                              ('Linux version linux-test', 'Linux version wrong'),
                              ('Will call new kernel at', 'no handoff at')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.verify(text.replace(before, after))
        for bad in (text + 'OpenSBI v1.8.1\n', text + 'MK_KEXEC_FAIL {}\n',
                    text + 'Kernel panic - not syncing: late\n', text + 'MK_FW_REJECT mode=1\n'):
            with self.assertRaises(ValueError):
                self.verify(bad)
        with self.assertRaises(ValueError):
            self.verify(text, status=124)
        crash = log('crash')
        for needle in ('Trigger a crash', 'Starting crashdump kernel...', 'Kernel panic'):
            with self.assertRaises(ValueError):
                self.verify(crash.replace(needle, 'missing'), 'crash')
        with self.assertRaises(ValueError):
            self.verify(crash + 'Kernel panic - not syncing: target panic\n', 'crash')

    def test_poweroff_and_single_intended_panic_are_required(self):
        text = log()
        for invalid in (text.replace('reboot: Power down\n', ''),
                        text.replace('Power down', 'Restarting system'),
                        text + 'reboot: Restarting system\n',
                        text.replace('reboot: Power down\n', '') + 'reboot: Power down\n' * 2,
                        'reboot: Power down\n' + text.replace('reboot: Power down\n', '')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.verify(invalid)
        crash = log('crash').replace('Starting crashdump kernel...',
                                    'Kernel panic - not syncing: unrelated failure\n'
                                    'Starting crashdump kernel...')
        with self.assertRaises(ValueError):
            self.verify(crash, 'crash')

    def test_capture_reservation_and_readable_riscv_core_header(self):
        text = log('crash')
        for kind, values in (
                ('BEGIN', dict(crash_size=0)), ('LOADED', dict(flags=0)),
                ('LOADED', dict(crash_loaded=0)), ('TARGET', dict(online='0-3')),
                ('TARGET', dict(vmcore_size=0)), ('TARGET', dict(vmcore_header='7f454c46')),
                ('TARGET', dict(vmcore_header='00' * 64))):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.verify(change(text, kind, **values), 'crash')
        header = json.loads(next(row.partition(' ')[2] for row in text.splitlines()
                                 if row.startswith('MK_KEXEC_TARGET ')))['vmcore_header']
        for offset in (4, 5, 16, 18, 20, 32, 52, 54, 56):
            data = bytearray.fromhex(header)
            data[offset] = 0
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.verify(change(text, 'TARGET', vmcore_header=data.hex()), 'crash')


if __name__ == '__main__':
    unittest.main()
