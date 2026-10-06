# SPDX-License-Identifier: GPL-2.0-only
"""Ordinary/crash file-kexec regression gate; no multikernel spawn claims."""
import json
import hashlib
from pathlib import Path
import re
import struct
import sys


def verify_artifacts(repo, build, bundle):
    """Authenticate the exact frozen inputs, not arbitrary manifest entries."""
    repo, build, bundle = Path(repo), Path(build), Path(bundle)
    digests = {}
    for line in (bundle / 'build-artifacts.sha256').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        if not match:
            raise ValueError('unsupported build hash record')
        path = (repo / match[2]).resolve()
        if path in digests:
            raise ValueError('duplicate build hash record')
        digests[path] = match[1]
    for source, frozen in (('arch/riscv/boot/Image', 'Image'),
                           ('vmlinux.unstripped', 'vmlinux.unstripped'), ('.config', 'kernel.config')):
        expected = digests.get((build / source).resolve())
        if expected is None or hashlib.sha256((bundle / frozen).read_bytes()).hexdigest() != expected:
            raise ValueError('unverified selected build artifact: ' + source)
    return dict(result='PASS', artifacts=['Image', 'vmlinux.unstripped', 'kernel.config'])


def verify_kexec(text, exit_status, mode, token, release, image_sha):
    if (exit_status or mode not in ('ordinary', 'crash') or
            not re.fullmatch(r'[0-9a-f]{32}', token) or
            not re.fullmatch(r'[0-9a-f]{64}', image_sha) or
            not re.fullmatch(r'[A-Za-z0-9_.+-]+', release)):
        raise ValueError('failed process or invalid expected scope')
    if re.search(r'MK_KEXEC_FAIL|MK_LIFECYCLE_|MK_TEST_|MK_FW_(REJECT|PENDING)|'
                 r'WARNING:|BUG:|Oops:|KASAN:|UBSAN:|soft lockup|hung task', text):
        raise ValueError('unexpected guest fault or multikernel scenario')
    matches = list(re.finditer(r'^MK_KEXEC_(\w+) ([^\n]*)$', text, re.MULTILINE))
    if [match[1] for match in matches] != ['BEGIN', 'LOADED', 'HANDOFF', 'TARGET', 'PASS']:
        raise ValueError('missing, duplicate or unordered handoff stages')
    records = [json.loads(match[2]) for match in matches]
    if any(row.get('mode') != mode or row.get('token') != token for row in records):
        raise ValueError('records do not match the externally supplied run token/mode')
    begin, loaded, handoff, target, passed = records
    crash = mode == 'crash'
    if (begin.get('release') != release or begin.get('image_sha') != image_sha or
            begin.get('online') != '0-3' or not begin.get('boot') or
            handoff.get('boot') != begin['boot'] or
            handoff.get('action') != ('sysrq-c' if crash else 'reboot-kexec') or
            target.get('release') != release or not target.get('boot') or
            target['boot'] == begin['boot'] or passed.get('boot') != target['boot'] or
            target.get('online') != ('0' if crash else '0-3')):
        raise ValueError('wrong boot identity, action, payload or CPU topology')
    for row, expected in ((begin, dict(loaded=0, crash_loaded=0)),
                          (loaded, dict(flags=10 if crash else 8,
                                        loaded=0 if crash else 1, crash_loaded=1 if crash else 0))):
        if any(type(row.get(key)) is not int or row[key] != value for key, value in expected.items()):
            raise ValueError('wrong file-load flags or slot state')
    size = begin.get('crash_size')
    if type(size) is not int or (size < 256 * 1024 * 1024 if crash else size != 0):
        raise ValueError('missing crash reservation or unintended ordinary reservation')

    firmware = list(re.finditer(r'^OpenSBI v[^\n]+', text, re.MULTILINE))
    boots = list(re.finditer(r'Linux version (\S+) ', text))
    allocations = list(re.finditer(r'kexec_file\(Image\): Loaded kernel at (0x[0-9a-f]+)\b', text))
    entries = list(re.finditer(r'kexec_file_load: type:(\d+), start:0x([0-9a-f]+) '
                              r'head:0x[0-9a-f]+ flags:0x([0-9a-f]+)\b', text))
    jumps = list(re.finditer(r'Will call new kernel at ([0-9a-f]+) from hart id ([0-9a-f]+)\b', text))
    if (len(firmware) != 1 or len(boots) != 2 or any(boot[1] != release for boot in boots) or
            len(allocations) != 1 or len(entries) != 1 or len(jumps) != 1):
        raise ValueError('missing exact firmware, Image load or machine-kexec execution evidence')
    address = int(allocations[0][1], 16)
    entry = int(entries[0][2], 16)
    if (address <= 0 or address % 0x200000 or entry <= 0 or int(jumps[0][1], 16) != entry or
            int(entries[0][1]) != (1 if crash else 0) or
            int(entries[0][3], 16) != loaded['flags'] or
            not firmware[0].start() < boots[0].start() < matches[0].start() <
                allocations[0].start() < entries[0].start() < matches[1].start() < matches[2].start() <
                jumps[0].start() < boots[1].start() < matches[3].start()):
        raise ValueError('wrong loaded entry or raw boot/handoff ordering')
    diagnostics = list(re.finditer(r'Kernel panic|Call Trace:|Trigger a crash|Starting crashdump kernel', text))
    if crash:
        window = text[matches[2].end():jumps[0].start()]
        triggers = ('Trigger a crash', 'Kernel panic - not syncing: sysrq triggered crash',
                    'Starting crashdump kernel...')
        positions = [window.find(needle) for needle in triggers]
        if (text.count('Kernel panic') != 1 or any(text.count(needle) != 1 for needle in triggers) or
                not 0 <= positions[0] < positions[1] < positions[2] or
                any(not matches[2].end() < event.start() < jumps[0].start() for event in diagnostics)):
            raise ValueError('crash diagnostics missing or outside the primary handoff window')
    elif diagnostics:
        raise ValueError('ordinary handoff unexpectedly crashed')

    vmcore_size = target.get('vmcore_size')
    if type(vmcore_size) is not int:
        raise ValueError('missing vmcore size observation')
    if crash:
        header = target.get('vmcore_header', '')
        if not re.fullmatch(r'[0-9a-f]{128}', header):
            raise ValueError('missing actual 64-byte vmcore header read')
        fields = struct.unpack('<16sHHIQQQIHHHHHH', bytes.fromhex(header))
        ident, kind, machine, version, _, phoff, _, _, ehsize, phsize, phnum, *_ = fields
        if (ident[:7] != b'\x7fELF\x02\x01\x01' or (kind, machine, version) != (4, 243, 1) or
                ehsize != 64 or phsize != 56 or phoff < 64 or not 0 < phnum < 65535 or
                vmcore_size < phoff + phsize * phnum):
            raise ValueError('vmcore is not a bounded ELF64 little-endian RISC-V core')
    elif vmcore_size != 0 or target.get('vmcore_header') != '-':
        raise ValueError('ordinary target unexpectedly exposes a crash dump')
    shutdowns = list(re.finditer(r'reboot: Power down\b', text))
    if (len(shutdowns) != 1 or shutdowns[0].start() <= matches[-1].end() or
            'reboot: Restarting system' in text):
        raise ValueError('missing target poweroff or unexpected machine reset')
    return dict(result='PASS', mode=mode, token=token, target_boot=target['boot'],
                image_start=address, machine_start=entry, vmcore_header_only=crash)


if __name__ == '__main__':
    if sys.argv[1] == '--artifacts':
        result = verify_artifacts(*sys.argv[2:5])
    else:
        result = verify_kexec(Path(sys.argv[1]).read_text(errors='replace'),
                              int(sys.argv[2]), *sys.argv[3:7])
    print(json.dumps(result, sort_keys=True))
