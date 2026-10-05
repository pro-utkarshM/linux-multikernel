#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Disposable native spawn RX session driver; existing TTY/control interfaces."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import termios
import threading
import time
import tty
from x86_host_init import marker

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')
MODES = ('spawn-close', 'spawn-hangup', 'spawn-overflow', 'spawn-offline')
# Linux asm-generic/ioctls.h; Python's termios does not expose this ioctl.
TIOCVHANGUP = 0x5437


def raw_mode(fd):
    # Never let the harness flush bytes that should expose stale delivery.
    tty.setraw(fd, termios.TCSANOW)


def read_exact(fd, expected):
    result = bytearray()
    deadline = time.monotonic() + 10
    while len(result) < len(expected):
        if time.monotonic() >= deadline:
            raise RuntimeError('spawn input delivery timed out')
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        chunk = os.read(fd, len(expected) - len(result))
        if not chunk:
            raise RuntimeError('spawn input closed early')
        result.extend(chunk)
    if result != expected:
        raise RuntimeError('stale or corrupt spawn session input')
    return bytes(result)


def state():
    value = json.loads((GATE / 'spawn_tty_status').read_text())
    if value['failed']:
        raise RuntimeError('native spawn RX observer timed out or overflowed')
    return value


def wait(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = state()
        if predicate(value):
            return value
        time.sleep(0.001)
    raise RuntimeError('native spawn RX boundary missing')


def online():
    # The lane deliberately requires exactly three logical CPUs before removal.
    value = Path('/sys/devices/system/cpu/online').read_text().strip()
    if value not in ('0-2', '0-1'):
        raise RuntimeError('unexpected spawn logical CPU topology: ' + value)
    return [0, 1, 2] if value == '0-2' else [0, 1]


def child(nonce, mode):
    number = MODES.index(mode) + 1
    session = number <= 2
    os.sched_setaffinity(0, {1})
    attrs = termios.tcgetattr(0)
    raw_mode(0)
    (GATE / 'spawn_tty_arm').write_text(f'{number} {nonce}')
    marker('SPAWN_READY', nonce=nonce, mode=mode)
    expected = 20000 if number == 3 else 32
    held = wait(lambda s: s['input'] == expected and len(s['events']) == 2)
    outcome, thread = {}, None
    # Keep the hung-up file alive until fresh input is checked, so a final
    # close cannot accidentally supply the flush that hangup must perform.
    old_hung_file = os.dup(0) if number == 2 else None
    if session:
        errors = []
        def close():
            try:
                if number == 2:
                    fcntl.ioctl(0, TIOCVHANGUP)
                for fd in (0, 1, 2):
                    os.close(fd)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=close, daemon=True)
        thread.start()
        held = wait(lambda s: s['drain_waiting'] and len(s['events']) == (5 if number == 2 else 4))
    elif number == 4:
        from kerf.topology import logical_to_apic
        from x86_nested_child_init import snapshot
        from x86_host_init import cli
        if online() != [0, 1, 2]:
            raise RuntimeError('offline target already absent')
        before = snapshot()
        victim = logical_to_apic()[2]
        if victim != before['owned_cpus'][-1]:
            raise RuntimeError('unexpected logical/physical offline target mapping')
        # The spawn wakeup path resumes pool-parked CPUs. Ordinary sysfs
        # offline enters a different dead loop and did not re-online in QEMU.
        cli('init', '--cpus=' + str(victim), '--memory=16MB', '--devices=none')
        outcome['pool_held'] = snapshot()
        outcome['offline'] = online()
        if (outcome['offline'] != [0, 1] or state()['worker_done']
                or outcome['pool_held']['pool_cpus'] != [victim]
                or outcome['pool_held']['owned_cpus'] != before['owned_cpus'][:-1]):
            raise RuntimeError('CPU offline did not overlap held worker')
    (GATE / 'spawn_tty_release').write_text('1')
    if session:
        thread.join(10)
        if thread.is_alive() or errors:
            raise RuntimeError('spawn close/hangup did not drain: ' + repr(errors))
        fd = os.open('/dev/mktty0', os.O_RDWR | os.O_NOCTTY)
        for target in (0, 1, 2):
            if fd != target:
                os.dup2(fd, target)
        if fd > 2:
            os.close(fd)
        raw_mode(0)
        marker('SPAWN_REOPENED', nonce=nonce, mode=mode)
        fresh = 'MKTTY_FRESH_' + nonce
        read_exact(0, fresh.encode())
        outcome.update(fresh=fresh, stale=False)
    else:
        received = read_exact(0, b'X' * (16384 if number == 3 else 32))
        outcome.update(received=len(received), sha256=hashlib.sha256(received).hexdigest())
    final = wait(lambda s: s['worker_done'] and (not session or s['reopened']))
    # The selected invocation is finished; this is an immediate trailing-byte
    # check, not a drain/proof of every later RX or flip-work invocation.
    if select.select([0], [], [], 0)[0] and os.read(0, 1):
        raise RuntimeError('duplicate or stale trailing input')
    if old_hung_file is not None:
        os.close(old_hung_file)
    if number == 4:
        from kerf.models import PoolMemoryRegion
        from kerf.pool_diff import PoolDiff
        from x86_nested_child_init import apply_pool
        if online() != [0, 1]:
            raise RuntimeError('victim CPU returned before worker continuation')
        result = apply_pool(PoolDiff(cpus_to_host=[victim]))
        outcome['pool_return'] = dict(result, **snapshot())
        if (result['status'] != 'applied'
                or outcome['pool_return']['owned_cpus'] != before['owned_cpus']
                or outcome['pool_return']['online_cpus'] != before['online_cpus']
                or outcome['pool_return']['pool_cpus']):
            raise RuntimeError('CPU return failed; retain pool park memory')
        chunks = [PoolMemoryRegion(base=base, size=size)
                  for base, size in outcome['pool_return']['chunks']]
        result = apply_pool(PoolDiff(memory_to_host=chunks))
        outcome['pool_retired'] = dict(result, **snapshot())
        if (result['status'] != 'applied' or outcome['pool_retired']['chunks']
                or outcome['pool_retired']['slot'] != '0' or outcome['pool_retired']['park'] != '0'):
            raise RuntimeError('pool park storage not retired; refuse parent reclaim')
        outcome['restored'] = online()
    termios.tcsetattr(0, termios.TCSANOW, attrs)
    marker('TTY_HELD', nonce=nonce, state=held,
           **({'offline': outcome['offline']} if number == 4 else {}))
    marker('TTY_COMPLETE', nonce=nonce, state=final, **outcome,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))


def host(console, mode):
    marker('TTY_BEGIN', nonce=console.nonce, mode=mode,
           taint=int(Path('/proc/sys/kernel/tainted').read_text()))
    console.send('spawn', mode=mode)
    console.wait('SPAWN_READY', mode=mode)
    size = 20000 if mode == 'spawn-overflow' else 32
    for offset in range(0, size, 4000):
        payload = b'X' * min(4000, size - offset)
        if os.write(console.fd, payload) != len(payload):
            raise RuntimeError('short native spawn payload write')
    if mode in ('spawn-close', 'spawn-hangup'):
        console.wait('SPAWN_REOPENED', mode=mode)
        fresh = ('MKTTY_FRESH_' + console.nonce).encode()
        if os.write(console.fd, fresh) != len(fresh):
            raise RuntimeError('short fresh spawn payload write')
    console.wait('TTY_HELD')
    console.wait('TTY_COMPLETE')
