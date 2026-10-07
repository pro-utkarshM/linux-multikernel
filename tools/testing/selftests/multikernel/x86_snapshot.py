#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded reads against the existing host controller gate in disposable QEMU."""
import errno
import os
from pathlib import Path
import time
from x86_lockdep import decode_record


def read_once(fd):
    started = time.monotonic()
    try:
        data, error = os.pread(fd, 65536, 0), 0
    except OSError as failure:
        data, error = None, failure.errno
    return dict(data=data, errno=error, elapsed_ms=int((time.monotonic() - started) * 1000))


def retry(fd):
    started = time.monotonic()
    for attempt in range(201):
        result = read_once(fd)
        elapsed = int((time.monotonic() - started) * 1000)
        if elapsed >= 2000:
            break
        if result['errno'] in (0, errno.ENODEV):
            return dict(result, attempts=attempt + 2, elapsed_ms=elapsed)
        if result['errno'] != errno.EAGAIN:
            raise OSError(result['errno'], 'unexpected kernfs snapshot read failure')
        time.sleep(0.01)
    raise TimeoutError('snapshot EAGAIN retry exceeded its bound')


def probe(blob, nonce, child, spare, *, removal=False):
    from kerf.dtc.parser import DeviceTreeParser
    from x86_host_init import BASE, NAME, marker
    from x86_admission_host_init import Operation, apply_overlay
    from verify_x86_snapshot import verify_records
    gate = Path('/sys/kernel/debug/mk-native-concurrency-test')
    initial = decode_record((gate / 'events').read_text())
    floor = max((event['seq'] for event in initial['events']), default=0)

    def state():
        value = decode_record((gate / 'events').read_text())
        value['events'] = [event for event in value['events'] if event['seq'] > floor]
        if value['overflow'] or any(event['point'] == 11 for event in value['events']):
            raise RuntimeError('lost/expired native snapshot gate')
        return value

    def writer():
        os.sched_setaffinity(0, {1})  # existing eight-CPU lane retains host logical0-2
        return apply_overlay(blob)

    descriptors = {}
    try:
        for name, path in (('root', BASE / 'device_tree'),
                           ('instance', BASE / 'instances' / NAME / 'device_tree')):
            descriptors[name] = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        (gate / 'gate_arm').write_text('1 0 30')
        operation = Operation(writer)
        deadline = time.monotonic() + 8
        while True:
            held = state()
            if held['active'] and held['point'] == 1 and any(
                    event['point'] == 9 and event['result'] == 1 for event in held['events']):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('controller did not reach actual resource-lock checkpoint')
            time.sleep(0.01)
        reads = {}
        for name, fd in descriptors.items():
            result = Operation(lambda fd=fd: read_once(fd)).finish(2)
            if result['errno'] != errno.EAGAIN or result['elapsed_ms'] >= 2000:
                raise RuntimeError('snapshot blocked or succeeded while controller held the lock')
            reads[name] = {key: result[key] for key in ('errno', 'elapsed_ms')}
        held = dict(nonce=nonce, gate=state(), reads=reads)
        if not held['gate']['active'] or held['gate']['point'] != 1:
            raise RuntimeError('controller hold ended before both read attempts')
        marker('SNAPSHOT_HELD', **held)
        (gate / 'gate_release').write_bytes(b'1')
        completed = operation.finish(15)
        if completed['status'] != 'applied':
            raise RuntimeError('resource writer failed')
        root = Operation(lambda: retry(descriptors['root'])).finish(3)
        instance = Operation(lambda: retry(descriptors['instance'])).finish(3)
        parser = DeviceTreeParser()
        pool = parser.parse_dtb_from_bytes(root['data']).hardware.cpus
        instance_cpus = None if instance['errno'] else dict(cpus=sorted(
            parser.parse_instance_dtb_from_bytes(instance['data']).resources.cpus))
        done = dict(nonce=nonce, removal=removal, gate=state(), **completed,
                    root=dict(cpus=sorted(pool.available), available=sorted(pool.available_free)),
                    instance=instance_cpus, stale_errno=instance['errno'],
                    retries={name: {key: result[key] for key in ('attempts', 'elapsed_ms')}
                             for name, result in (('root', root), ('instance', instance))})
        errors = verify_records(held, done, child, spare, removal)
        if errors:
            raise RuntimeError(errors)
        marker('SNAPSHOT_SETTLED', **done)
        return completed
    finally:
        for fd in descriptors.values():
            os.close(fd)
