#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Real instance removal while a sender retains its original lookup reference."""
import json
import os
from pathlib import Path
import sys
import termios
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import BASE, NAME, cli, marker
from x86_nested_host_init import main
from x86_admission_host_init import Operation, pool_cpus
from x86_lockdep import probe_child

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


def wait(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = json.loads((GATE / 'destroy_status').read_text())
        if state['failed']:
            raise RuntimeError(f'native destruction gate failed: {state}')
        if predicate(state):
            return state
        time.sleep(0.001)
    raise RuntimeError(f'native destruction observation deadline expired: {state}')


def stop(fd, pending, nonce, child, spare):
    pending = probe_child(fd, pending, nonce)
    cli('kill', NAME)
    return pending


def unload(fd, pending, nonce, child, spare):
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD, KEXEC_MULTIKERNEL, KEXEC_MK_ID
    os.sched_setaffinity(0, {2})
    (GATE / 'destroy_arm').write_text(nonce)
    initial = wait(lambda s: len(s['events']) == 1, 3)
    marker('DESTROY_ARMED', nonce=nonce, state=initial,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    termios.tcdrain(1)
    def unloader():
        os.sched_setaffinity(0, {1})
        kexec_file_unload(KEXEC_MULTIKERNEL | KEXEC_MK_ID(1) | KEXEC_FILE_UNLOAD)
    Operation(unloader).finish(10)
    wait(lambda s: len(s['events']) == 3, 3)
    return pending


def destroy(fd, pending, nonce, child, spare):
    termios.tcdrain(1)  # complete the preceding UNLOADED record before removal printk
    from kerf.runtime import DeviceTreeManager
    def remover():
        os.sched_setaffinity(0, {1})
        tx = DeviceTreeManager().apply_removal_overlay(NAME)
        return int(tx), (BASE / 'overlays' / ('tx_' + str(tx)) / 'status').read_text().strip()
    if 'mk_snapshot_test=1' in Path('/proc/cmdline').read_text().split():
        from kerf.dtc.overlay import OverlayGenerator
        from x86_snapshot import probe
        # Construct the removal request before the real controller lock is held.
        completed = probe(bytes(OverlayGenerator().generate_removal_overlay(NAME)),
                          nonce, child, spare, removal=True)
        transaction, result = completed['transaction'], completed['status']
    else:
        transaction, result = Operation(remover).finish(10)
    wait(lambda s: s['retired'] and len(s['events']) == 5, 3)
    (GATE / 'destroy_probe').write_bytes(b'1')
    held = wait(lambda s: s['probed'], 1)
    assigned = pool_cpus()
    absent = not (BASE / 'instances' / NAME).exists()
    if result != 'applied' or not absent or assigned != sorted(child + spare):
        raise RuntimeError('instance removal or synchronous pool return not proven')
    marker('DESTROY_HELD', nonce=nonce, state=held, transaction=transaction,
           status=result, instance_absent=absent, pool_cpus=assigned)
    termios.tcdrain(1)
    (GATE / 'destroy_release').write_bytes(b'1')
    final = wait(lambda s: s['sent'] and len(s['events']) == 11, 5)
    marker('DESTROY_COMPLETE', nonce=nonce, state=final,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    termios.tcdrain(1)
    return pending


if __name__ == '__main__':
    main(stop, profile='destroy', after_halt=unload, after_unload=destroy)
