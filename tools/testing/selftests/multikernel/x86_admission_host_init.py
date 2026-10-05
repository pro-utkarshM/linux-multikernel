#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Real requester/controller admission and uncertain-add drain in QEMU only."""
import copy
import errno
import json
import os
from pathlib import Path
import select
import sys
import threading
import time

sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import BASE, NAME, marker, ownership, status
from x86_nested_host_init import main
from x86_lockdep import probe_child


class Operation:
    def __init__(self, function):
        self.result = None
        def run():
            try:
                self.result = function()
            except Exception as error:
                self.result = error
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def finish(self, timeout=15):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise RuntimeError('native operation did not finish; retain resources')
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def update(cpus):
    from kerf.dtc.parser import DeviceTreeParser
    from kerf.dtc.overlay import OverlayGenerator
    old = DeviceTreeParser().parse_instance_dtb_from_bytes(
        (BASE / 'instances' / NAME / 'device_tree').read_bytes())
    new = copy.deepcopy(old)
    new.resources.cpus = cpus
    blob = bytes(OverlayGenerator().generate_update_overlay(NAME, old, new))
    previous = set((BASE / 'overlays').glob('tx_*'))
    start = time.monotonic()
    with (BASE / 'overlays/new').open('wb', buffering=0) as stream:
        if stream.write(blob) != len(blob):
            raise RuntimeError('short parent overlay write')
    elapsed = int((time.monotonic() - start) * 1000)
    created = set((BASE / 'overlays').glob('tx_*')) - previous
    if len(created) != 1:
        raise RuntimeError('ambiguous parent overlay transaction')
    transaction = created.pop()
    return dict(transaction=int(transaction.name.removeprefix('tx_')),
                status=(transaction / 'status').read_text().strip(), elapsed_ms=elapsed)


def pool_cpus():
    state = json.loads(Path('/sys/kernel/debug/mk-native-concurrency-test/local_snapshot').read_text())
    if state['instance'] != 0:
        raise RuntimeError('not parent pool snapshot')
    ids = state['pool_cpus']
    if (not isinstance(ids, list) or any(type(cpu) is not int or not 0 <= cpu < (1 << 64) - 1
                                        for cpu in ids) or len(set(ids)) != len(ids)):
        raise RuntimeError('invalid parent physical CPU set')
    return sorted(ids)


class Console:
    def __init__(self, fd, pending, nonce):
        self.fd, self.pending, self.nonce = fd, pending, nonce

    def send(self, op, **fields):
        command = f'process {self.nonce} ' + json.dumps(dict(op=op, **fields)) + '\n'
        data = command.encode()
        if os.write(self.fd, data) != len(data):
            raise RuntimeError('short process command')

    def wait(self, name, timeout=15, **fields):
        deadline = time.monotonic() + timeout
        captured = 0
        while time.monotonic() < deadline:
            while b'\n' in self.pending:
                line, _, self.pending = self.pending.partition(b'\n')
                text = line.decode(errors='replace').rstrip('\r')
                print(text, flush=True)
                if text.startswith('MK_X86_FAIL '):
                    raise RuntimeError('child process test failed; retain resources')
                if text.startswith('MK_X86_' + name + ' '):
                    value = json.loads(text.partition(' ')[2])
                    if value.get('nonce') != self.nonce or any(value.get(k) != v for k, v in fields.items()):
                        raise RuntimeError('uncorrelated process reply')
                    return value
            if not select.select([self.fd], [], [], 0.1)[0]:
                continue
            chunk = os.read(self.fd, 8192)
            if not chunk:
                raise RuntimeError('child console disappeared')
            self.pending.extend(chunk)
            captured += len(chunk)
            if captured > 1024 * 1024:
                raise RuntimeError('child console flood')
        raise RuntimeError(f'child {name} response deadline expired')

    def command(self, op, **fields):
        self.send(op, **fields)
        return self.wait('PROCESS_REPLY', op=op)


def admission(fd, pending, nonce, child, spare):
    from kerf.kill.main import halt_multikernel
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD
    from kerf.load.main import KEXEC_MULTIKERNEL, KEXEC_MK_ID
    console = Console(fd, pending, nonce)
    cpu = child[-1]
    for mode, point in (('controller-first', 1), ('worker-first', 2)):
        marker('ADMISSION_BEGIN', nonce=nonce, mode=mode, cpu=cpu)
        console.command('arm', point=point, cpu=cpu)
        if point == 1:
            console.command('controller', mode=mode)
        else:
            removal = Operation(lambda: update(child[:-1]))
        console.send('held', mode=mode, point=point)
        console.wait('ADMISSION_HELD', mode=mode)
        if point == 1:
            result = update(child[:-1])
            if result['status'] != 'failed' or ownership() != child or pool_cpus() != spare:
                raise RuntimeError('busy admission did not retain ownership')
            marker('ADMISSION_REJECTED', nonce=nonce, mode=mode, **result,
                   assigned_cpus=ownership(), pool_cpus=pool_cpus())
        else:
            console.command('controller', mode=mode)
            console.send('waiting', mode=mode)
            console.wait('ADMISSION_CONTROLLER_WAITING', mode=mode)
        console.command('release')
        console.send('finish', mode=mode)
        console.wait('ADMISSION_CONTROLLER_DONE', mode=mode)
        console.send('retire', mode=mode)
        console.wait('ADMISSION_RETIRED', mode=mode)
        # Do not remotely remove a CPU while a child-local park area exists.
        # That separate nested-slot handoff is not qualified by this lane.
        result = update(child[:-1]) if point == 1 else removal.finish()
        if result['status'] != 'applied' or ownership() != child[:-1]:
            raise RuntimeError('CPU removal did not settle')
        marker('ADMISSION_REMOVED', nonce=nonce, mode=mode, **result,
               assigned_cpus=ownership(), pool_cpus=pool_cpus())
        result = update(child)
        state = console.command('snapshot')['state']
        if result['status'] != 'applied' or ownership() != child or state['online_cpus'] != child:
            raise RuntimeError('CPU re-add did not settle')
        marker('ADMISSION_SETTLED', nonce=nonce, mode=mode, **result,
               assigned_cpus=ownership(), **state)

    mode, cpu = 'timeout-drain', spare[0]
    marker('ADMISSION_BEGIN', nonce=nonce, mode=mode, cpu=cpu)
    console.command('arm', point=3, cpu=cpu)
    addition = Operation(lambda: update(sorted(child + [cpu])))
    console.send('held', mode=mode, point=3)
    console.wait('ADMISSION_HELD', mode=mode)
    result = addition.finish()
    state = console.command('snapshot')['state']
    owned = sorted(child + [cpu])
    if (result['status'] != 'failed' or result['elapsed_ms'] < 9000
            or ownership() != owned or pool_cpus() != spare[1:] or state['online_cpus'] != owned):
        raise RuntimeError('uncertain add did not retain assigned CPU')
    try:
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
    except OSError as error:
        if error.errno != errno.EBUSY:
            raise
        unload_errno = error.errno
    else:
        raise RuntimeError('active uncertain instance was unloaded')
    marker('ADMISSION_TIMEOUT_RETAINED', nonce=nonce, **result,
           assigned_cpus=ownership(), pool_cpus=pool_cpus(), child=state,
           unload_errno=unload_errno, instance_status=status('active'))
    halt = Operation(lambda: halt_multikernel(1, force=False))
    console.send('drain')
    console.wait('ADMISSION_DRAIN_WAITING')
    if not halt.thread.is_alive():
        raise RuntimeError('shutdown returned before accepted worker retired')
    console.pending = probe_child(fd, console.pending, nonce)
    # No reply is required: the real shutdown may stop PID1 immediately.
    console.send('release')
    halt.finish()
    marker('ADMISSION_COMPLETE', nonce=nonce, status=status('loaded'), assigned_cpus=ownership())
    return console.pending


if __name__ == '__main__':
    main(admission, profile='admission')
