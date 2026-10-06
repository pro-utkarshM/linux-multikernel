#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Ordinary/crash file-kexec from an isolated QEMU primary, never a spawn."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import traceback


def marker(kind, **values):
    print('MK_KEXEC_' + kind + ' ' + json.dumps(values, sort_keys=True), flush=True)


def parse_scope(command_line):
    pairs = [word.split('=', 1) for word in command_line.split()
             if word.startswith('mk_kexec_') and '=' in word]
    options = dict(pairs)
    mode, token = options.get('mk_kexec_mode'), options.get('mk_kexec_token', '')
    if (len(pairs) != 4 or len(options) != 4 or
            options.get('mk_kexec_guard') != 'vm-v1' or options.get('mk_kexec_stage') != 'primary' or
            mode not in ('ordinary', 'crash') or not re.fullmatch('[0-9a-f]{32}', token)):
        raise ValueError('refusing operations outside the declared QEMU kexec scope')
    return mode, token


def main(mode, token):
    for kind, path in (('sysfs', '/sys'), ('devtmpfs', '/dev')):
        subprocess.run(['/bin/busybox', 'mount', '-t', kind, kind, path], check=True)
    crash = mode == 'crash'
    sys.path.insert(0, '/usr/lib/python3/dist-packages')
    from kerf.load.main import kexec_file_load, KEXEC_FILE_DEBUG

    def value(name):
        return int((Path('/sys/kernel/kexec') / name).read_text())

    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    release = Path('/payload/vmlinux.release').read_text().strip()
    image_sha = hashlib.sha256(Path('/payload/vmlinux').read_bytes()).hexdigest()
    assert image_sha == Path('/payload/vmlinux.sha256').read_text().strip()
    assert platform.release() == release
    online = Path('/sys/devices/system/cpu/online').read_text().strip()
    assert online == '0-3'
    assert value('loaded') == value('crash_loaded') == 0
    reservation = value('crash_size')
    assert reservation >= 256 * 1024 * 1024 if crash else reservation == 0
    marker('BEGIN', mode=mode, token=token, boot=boot, release=release, online=online,
           image_sha=image_sha, loaded=0, crash_loaded=0, crash_size=reservation)
    cmdline = ('console=ttyS0,115200 rdinit=/init panic=0 loglevel=7 '
               'mk_kexec_guard=vm-v1 mk_kexec_stage=target '
               f'mk_kexec_mode={mode} mk_kexec_token={token}')
    if crash:
        cmdline += ' nr_cpus=1'
    # Record the final entry (possibly purgatory), never KEXEC_MULTIKERNEL.
    flags = KEXEC_FILE_DEBUG | (2 if crash else 0)
    with open('/payload/vmlinux', 'rb') as kernel, \
            open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
        assert kexec_file_load(kernel.fileno(), initrd.fileno(), cmdline, flags) == 0
    loaded, crash_loaded = value('loaded'), value('crash_loaded')
    assert (loaded, crash_loaded) == ((0, 1) if crash else (1, 0))
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot
    marker('LOADED', mode=mode, token=token, flags=flags, loaded=loaded, crash_loaded=crash_loaded)
    os.sync()
    marker('HANDOFF', mode=mode, token=token, boot=boot,
           action='sysrq-c' if crash else 'reboot-kexec')
    if crash:
        Path('/proc/sysrq-trigger').write_text('c\n')
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.reboot.argtypes = [ctypes.c_int]
        libc.reboot.restype = ctypes.c_int
        if libc.reboot(0x45584543):  # LINUX_REBOOT_CMD_KEXEC
            raise OSError(ctypes.get_errno(), 'reboot(KEXEC)')
    raise AssertionError('kernel handoff unexpectedly returned')


if __name__ == '__main__':
    if os.getpid() != 1 or platform.machine() != 'riscv64':
        raise SystemExit('refusing operations outside RISC-V guest PID1')
    # Validate scope outside the failure handler that powers off the test VM.
    subprocess.run(['/bin/busybox', 'mount', '-t', 'proc', 'proc', '/proc'], check=True)
    scope = parse_scope(Path('/proc/cmdline').read_text())
    try:
        main(*scope)
    except Exception as error:
        marker('FAIL', error=repr(error))
        traceback.print_exc()
    os.sync()
    ctypes.CDLL(None).reboot(0x4321FEDC)
    while True:
        time.sleep(1)
