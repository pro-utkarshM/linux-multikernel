#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build from an explicit clean source and freeze revision/config/binary binding."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from prepare_x86_child import command, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--kernel-build', type=Path, required=True,
                        help='new output directory with an existing .config')
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=2)
    args = parser.parse_args()
    source, build = args.source.resolve(), args.kernel_build.resolve()
    if not (build / '.config').is_file() or (build / 'mk-x86-build.json').exists():
        raise RuntimeError('existing .config and unused provenance path required')
    revision = command('git', '-C', str(source), 'rev-parse', 'HEAD')
    tree = command('git', '-C', str(source), 'rev-parse', 'HEAD^{tree}')
    if command('git', '-C', str(source), 'status', '--porcelain'):
        raise RuntimeError('source must be clean before building')
    make = ['make', '-C', str(source), 'ARCH=x86_64', 'O=' + str(build),
            'CC=gcc', 'HOSTCC=gcc', 'LD=ld', 'OBJCOPY=objcopy']
    subprocess.run(make + ['olddefconfig'], check=True)
    config_hash = digest(build / '.config')
    started = time.time_ns()
    invocation = make + ['-j' + str(args.jobs), 'vmlinux', 'bzImage']
    subprocess.run(invocation, check=True)
    if (command('git', '-C', str(source), 'rev-parse', 'HEAD') != revision
            or command('git', '-C', str(source), 'status', '--porcelain')
            or digest(build / '.config') != config_hash):
        raise RuntimeError('source/config changed during build; no proof emitted')
    proof = {'schema': 1, 'revision': revision, 'source_tree': tree,
             'source': str(source), 'build_exit': 0, 'command': invocation,
             'started_ns': started, 'finished_ns': time.time_ns(),
             'gcc': command('gcc', '--version'),
             'artifacts': {name: digest(build / name) for name in
                           ('.config', 'vmlinux', 'arch/x86/boot/bzImage')}}
    with (build / 'mk-x86-build.json').open('x') as output:
        json.dump(proof, output, indent=2)
        output.write('\n')
    print('BUILD_PROVENANCE_BOUND revision=' + revision, flush=True)


if __name__ == '__main__':
    main()
