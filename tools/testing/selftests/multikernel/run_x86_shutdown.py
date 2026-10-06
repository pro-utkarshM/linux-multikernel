#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run only a frozen six-CPU QEMU shutdown rejection bundle, preserving logs."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
from verify_x86_child import validate_bundle
from verify_x86_shutdown import MODES, terminal_record, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--output', type=Path, required=True, help='existing persistent output parent')
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    if Path(__file__).resolve().parent != bundle:
        raise RuntimeError('execute the frozen runner inside the bundle')
    errors = validate_bundle(bundle, args.revision)
    required = {'CONFIG_MK_X86_NATIVE_CONFIRM_TEST=y', 'CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST=y',
                'CONFIG_MAGIC_SYSRQ=y'}
    if errors or not required <= set((bundle / 'kernel.config').read_text().splitlines()):
        raise RuntimeError(f'invalid source-bound private test bundle: {errors}')
    output = Path(tempfile.mkdtemp(prefix=args.mode + '-', dir=args.output.resolve()))
    print(f'Evidence: {output}', flush=True)
    command = ['qemu-system-x86_64', '-machine', 'q35', '-accel', 'tcg,thread=multi',
               '-cpu', 'max', '-smp', '6', '-m', '3072', '-kernel', str(bundle / 'bzImage'),
               '-initrd', str(bundle / 'host-initrd.cpio.gz'), '-append',
               'console=ttyS0,115200 rdinit=/init panic=0 kernelcore=1G log_buf_len=4M '
               'mk_test=x86-host nokaslr mk_native_confirm_test=1 mk_x86_halt=' + args.mode,
               '-nographic', '-monitor', 'none', '-nic', 'none', '-no-reboot',
               '-debugcon', 'file:' + str(output / 'debug.log')]
    metadata = dict(command=command, revision=args.revision, mode=args.mode, bundle=str(bundle),
                    qemu_version=subprocess.check_output(['qemu-system-x86_64', '--version'], text=True))
    (output / 'command.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with (output / 'serial.log').open('xb') as serial:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=serial, stderr=subprocess.STDOUT)
        try:
            deadline, sent = time.monotonic() + 240, False
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError('VM deadline; retained state not qualified')
                debug = output / 'debug.log'
                if debug.exists():
                    data = debug.read_bytes()
                    if len(data) > 512:
                        raise RuntimeError('overflow/duplicate terminal output')
                    if b'\n' in data:
                        terminal_record(data.decode())
                        if not sent:
                            process.stdin.write(data)
                            process.stdin.flush()
                            sent = True
                time.sleep(0.05)
            if process.returncode:
                errors.append(f'QEMU exited {process.returncode}')
            if not sent:
                errors.append('VM exited without terminal observation relay')
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            errors.append(str(error))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdin.close()
    try:
        errors += verify((output / 'serial.log').read_text(errors='replace'),
                         (output / 'debug.log').read_text(), args.mode, args.revision)
    except (OSError, UnicodeError) as error:
        errors.append(str(error))
    (output / 'result.json').write_text(json.dumps(dict(qemu_exit=process.returncode,
                                                      errors=errors, passed=not errors), indent=2) + '\n')
    for error in errors:
        print('FAIL:', error)
    if errors:
        return 1
    print('PASS: terminal permission rejected and resources retained; no recovery attempted')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
