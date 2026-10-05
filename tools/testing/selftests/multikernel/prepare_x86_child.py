#!/usr/bin/env python3
"""Offline executing-child extension of Nickolaev's pinned #35 packer.

Keeps #35's newc/gzip packing flow and integrated Kerf source. Python PID 1
replaces its shell init because installed initcpio BusyBox has no mount applet.
No packages, compilers, network, deletion, or reused output directories.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS_REV = '48507f176520b11a655344510b1b865b037e527f'
KERF_REV = '38daa5687d6748846ffd003599a3bfba29785cd6'


def command(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_build_proof(build, revision):
    proof = json.loads((build / 'mk-x86-build.json').read_text())
    required = ('.config', 'vmlinux', 'arch/x86/boot/bzImage')
    if (proof.get('schema') != 1 or proof.get('revision') != revision
            or proof.get('build_exit') != 0
            or not re.fullmatch(r'[0-9a-f]{40}', proof.get('source_tree', ''))
            or set(proof.get('artifacts', {})) != set(required)
            or any(digest(build / name) != proof['artifacts'][name] for name in required)):
        raise RuntimeError('missing, stale or mismatched build-time provenance')
    return proof


def dependencies(paths):
    libraries = set()
    for path in paths:
        # ldd may resolve an alias, but the kernel opens PT_INTERP literally.
        headers = command('readelf', '-l', str(path))
        interpreter = re.search(r'\[Requesting program interpreter: (.*?)\]', headers)
        if interpreter:
            libraries.add(Path(interpreter.group(1)))
        result = subprocess.run(['ldd', str(path)], capture_output=True, text=True, timeout=30)
        if 'not found' in result.stdout:
            raise RuntimeError(f'unresolved dependency for {path}: {result.stdout}')
        if result.returncode and not any(text in result.stderr + result.stdout
                                        for text in ('not a dynamic executable', 'statically linked')):
            raise RuntimeError(f'ldd failed for {path}: {result.stderr}')
        for line in result.stdout.splitlines():
            match = re.search(r'(?:=>\s+)?(/\S+)\s+\(', line)
            if match:
                libraries.add(Path(match.group(1)))
    return sorted(libraries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true', help='package into a fresh directory; never launch')
    parser.add_argument('--profile', choices=('halt', 'nested', 'admission', 'rcu', 'registry', 'tty', 'writer', 'destroy'), default='halt',
                        help='six-CPU halt or eight-CPU nested/admission lane')
    parser.add_argument('--revision', help='main-attested full kernel source revision, required to prepare')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--kerf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='existing parent for a fresh immutable bundle')
    args = parser.parse_args()
    assert platform.machine() == 'x86_64'
    harness, kerf = args.harness.resolve(), args.kerf.resolve()
    for tree, revision in ((harness, HARNESS_REV), (kerf, KERF_REV)):
        if command('git', '-C', str(tree), 'rev-parse', 'HEAD') != revision:
            raise RuntimeError(f'pin mismatch: {tree}')
        if command('git', '-C', str(tree), 'status', '--porcelain'):
            raise RuntimeError(f'dirty dependency checkout: {tree}')
    config = args.kernel_build / '.config'
    required = [line for line in (HERE / 'x86_child.config').read_text().splitlines()
                if line.startswith('CONFIG_')]
    actual = set(config.read_text().splitlines())
    if args.profile != 'halt':
        required.append('CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST=y')
    missing = [line for line in required if line not in actual]
    if missing:
        raise RuntimeError('missing built-ins: ' + ', '.join(missing))
    for name in ('cpio', 'gzip', 'ldd', 'find', 'sort', 'readelf', 'bash'):
        if not shutil.which(name):
            raise RuntimeError(f'missing host dependency: {name}; nothing installed')
    busybox = Path('/usr/lib/initcpio/busybox')
    python = Path(sys.executable).resolve()
    for path in (busybox, python, args.kernel_build / 'vmlinux'):
        if 'Advanced Micro Devices X86-64' not in command('readelf', '-h', str(path)):
            raise RuntimeError(f'not an x86-64 ELF: {path}')
    if 'dmesg' not in command(str(busybox), '--list').splitlines():
        raise RuntimeError('BusyBox lacks dmesg')
    sys.path.insert(0, str(kerf / 'src'))
    # This is a local x86 userspace import check, NOT kernel compatibility proof.
    click = importlib.import_module('click')
    libfdt = importlib.import_module('libfdt')
    extension = importlib.import_module('_libfdt')
    importlib.import_module('kerf.cli')
    stdlib = Path(sysconfig.get_path('stdlib'))
    runtime_libraries = dependencies([python, busybox, Path(extension.__file__),
                                      *sorted((stdlib / 'lib-dynload').glob('*.so'))])
    source_head = command('git', '-C', str(args.source), 'rev-parse', 'HEAD')
    proof = validate_build_proof(args.kernel_build, source_head)
    if (Path(proof['source']).resolve() != args.source.resolve()
            or proof['source_tree'] != command('git', '-C', str(args.source),
                                               'rev-parse', 'HEAD^{tree}')):
        raise RuntimeError('build provenance names a different source checkout or tree')
    prefix = 'x86' if args.profile == 'halt' else 'x86_' + args.profile
    host_init, child_init = (HERE / (prefix + suffix) for suffix in ('_host_init.py', '_child_init.py'))
    inputs = [args.kernel_build / 'arch/x86/boot/bzImage', args.kernel_build / 'vmlinux',
              config, args.kernel_build / 'mk-x86-build.json',
              HERE / 'x86_host_init.py', HERE / 'x86_child_init.py',
              HERE / 'verify_x86_child.py', HERE / 'x86_child.config', Path(__file__).resolve()]
    if args.profile != 'halt':
        inputs += [HERE / 'x86_nested_host_init.py', HERE / 'x86_nested_child_init.py',
                   HERE / 'verify_x86_nested.py']
    if args.profile == 'admission':
        inputs += [host_init, child_init, HERE / 'verify_x86_admission.py']
    if args.profile == 'rcu':
        inputs += [host_init, child_init, HERE / 'verify_x86_rcu.py', HERE / 'x86_admission_host_init.py']
    if args.profile == 'registry':
        inputs += [host_init, child_init, HERE / 'verify_x86_registry.py',
                   HERE / 'x86_admission_host_init.py', HERE / 'x86_rcu_host_init.py']
    if args.profile == 'tty':
        inputs += [host_init, child_init, HERE / 'verify_x86_tty.py',
                   HERE / 'x86_admission_host_init.py', HERE / 'x86_kmsg.py']
    if args.profile == 'writer':
        inputs += [host_init, child_init, HERE / 'verify_x86_writer.py', HERE / 'x86_admission_host_init.py']
    if args.profile == 'destroy':
        inputs += [host_init, child_init, HERE / 'verify_x86_destroy.py', HERE / 'x86_admission_host_init.py']
    hashes = {str(path.resolve()): digest(path) for path in inputs}
    print(json.dumps({'mode': 'prepare' if args.prepare else 'HOST_DRY_RUN_ONLY',
                      'source_head': source_head, 'artifact_revision': args.revision or 'UNATTESTED',
                      'harness': HARNESS_REV, 'kerf': KERF_REV, 'busybox': str(busybox),
                      'python': str(python), 'shared_libraries': len(runtime_libraries),
                      'required_config': 'present', 'input_sha256': hashes,
                      'native_operations': 0, 'vm_launch': False}, indent=2), flush=True)
    if not args.prepare:
        return
    if not args.revision or args.revision != source_head:
        raise RuntimeError('prepare requires --revision matching main-attested, current source HEAD')
    if command('git', '-C', str(args.source), 'status', '--porcelain'):
        raise RuntimeError('kernel source worktree is dirty')

    bundle = Path(tempfile.mkdtemp(prefix='x86-child-', dir=args.output.resolve()))
    root = bundle / 'rootfs'
    for directory in ('bin', 'sbin', 'dev', 'proc', 'sys', 'tmp', 'run', 'var/run', 'payload', 'usr/bin'):
        (root / directory).mkdir(parents=True, exist_ok=True)

    def install(source, relative):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if digest(target) != digest(source):
                raise RuntimeError(f'copy collision: {target}; partial output preserved')
        else:
            shutil.copy2(source, target)

    # Offline adaptation of #35 prepare-kerf-runtime.sh; no apt/pip bootstrap.
    shutil.copytree(stdlib, root / 'usr/lib' / stdlib.name,
                    ignore=shutil.ignore_patterns('site-packages', '__pycache__', '*.pyc',
                                                 'test', 'tests', 'tkinter', 'idlelib', 'ensurepip'))
    site = root / 'usr/lib/python3/dist-packages'
    site.mkdir(parents=True)
    for source, name in ((Path(click.__file__).parent, 'click'), (kerf / 'src/kerf', 'kerf')):
        shutil.copytree(source, site / name,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    install(Path(libfdt.__file__), 'usr/lib/python3/dist-packages/libfdt.py')
    install(Path(extension.__file__), 'usr/lib/python3/dist-packages/' + Path(extension.__file__).name)
    install(python, 'usr/bin/python3')
    install(busybox, 'bin/busybox')
    for library in runtime_libraries:
        install(library, str(library).lstrip('/'))
    install(host_init, 'init')
    if args.profile != 'halt':
        install(HERE / 'x86_host_init.py', 'usr/lib/python3/dist-packages/x86_host_init.py')
    if args.profile in ('admission', 'rcu', 'registry', 'tty', 'writer', 'destroy'):
        for name in ('x86_nested_host_init.py', 'x86_nested_child_init.py'):
            install(HERE / name, 'usr/lib/python3/dist-packages/' + name)
    if args.profile in ('rcu', 'registry', 'tty', 'writer', 'destroy'):
        install(HERE / 'x86_admission_host_init.py', 'usr/lib/python3/dist-packages/x86_admission_host_init.py')
    if args.profile == 'registry':
        install(HERE / 'x86_rcu_host_init.py', 'usr/lib/python3/dist-packages/x86_rcu_host_init.py')
    if args.profile == 'tty':
        install(HERE / 'x86_kmsg.py', 'usr/lib/python3/dist-packages/x86_kmsg.py')
    (root / 'init').chmod(0o755)
    (root / 'payload/source-revision').write_text(args.revision + '\n')
    # Reuse the same offline Python runtime; the child has no kernel payload.
    child = bundle / 'child-rootfs'
    shutil.copytree(root, child)
    shutil.copy2(child_init, child / 'init')
    (child / 'init').chmod(0o755)

    def pack(tree, archive_path):
        for path in sorted(tree.rglob('*'), reverse=True):
            os.utime(path, (0, 0), follow_symlinks=False)
        os.utime(tree, (0, 0))
        with archive_path.open('xb') as archive:
            subprocess.run(['bash', '-o', 'pipefail', '-c',
                            'find . -print0 | LC_ALL=C sort -z | '
                            'cpio --null -o --format=newc --owner=0:0 --reproducible | gzip -n -9'],
                           cwd=tree, stdout=archive, check=True)

    pack(child, bundle / 'child-initrd.cpio.gz')
    install(bundle / 'child-initrd.cpio.gz', 'payload/child-initrd.cpio.gz')
    shutil.copy2(HERE / 'verify_x86_child.py', bundle / 'verify_x86_child.py')
    if args.profile != 'halt':
        shutil.copy2(HERE / 'verify_x86_nested.py', bundle / 'verify_x86_nested.py')
    if args.profile == 'admission':
        shutil.copy2(HERE / 'verify_x86_admission.py', bundle / 'verify_x86_admission.py')
    if args.profile == 'rcu':
        shutil.copy2(HERE / 'verify_x86_rcu.py', bundle / 'verify_x86_rcu.py')
    if args.profile == 'registry':
        shutil.copy2(HERE / 'verify_x86_registry.py', bundle / 'verify_x86_registry.py')
    if args.profile == 'tty':
        shutil.copy2(HERE / 'verify_x86_tty.py', bundle / 'verify_x86_tty.py')
        shutil.copy2(HERE / 'x86_kmsg.py', bundle / 'x86_kmsg.py')
    if args.profile == 'writer':
        shutil.copy2(HERE / 'verify_x86_writer.py', bundle / 'verify_x86_writer.py')
    if args.profile == 'destroy':
        shutil.copy2(HERE / 'verify_x86_destroy.py', bundle / 'verify_x86_destroy.py')
    install(args.kernel_build / 'vmlinux', 'payload/vmlinux')
    shutil.copy2(args.kernel_build / 'arch/x86/boot/bzImage', bundle / 'bzImage')
    shutil.copy2(config, bundle / 'kernel.config')
    shutil.copy2(args.kernel_build / 'mk-x86-build.json', bundle / 'mk-x86-build.json')
    if any(digest(Path(path)) != expected for path, expected in hashes.items()):
        raise RuntimeError('inputs changed while preparing; partial output preserved')
    if command('git', '-C', str(args.source), 'rev-parse', 'HEAD') != args.revision:
        raise RuntimeError('source HEAD changed during preparation; partial output preserved')
    # The same archive format/order as #35. Output is newly created, never reused.
    pack(root, bundle / 'host-initrd.cpio.gz')
    (bundle / 'provenance.json').write_text(json.dumps({
        'profile': args.profile, 'kernel_revision': args.revision, 'harness_revision': HARNESS_REV,
        'kerf_revision': KERF_REV, 'inputs': hashes, 'native_tests_run': False}, indent=2) + '\n')
    files = sorted(path for path in bundle.rglob('*') if path.is_file())
    with (bundle / 'SHA256SUMS').open('x') as manifest:
        for path in files:
            manifest.write(f'{digest(path)}  {path.relative_to(bundle)}\n')
    print(f'PACKAGED_ONLY bundle={bundle} native_tests_run=0 vm_launch=0')


if __name__ == '__main__':
    main()
