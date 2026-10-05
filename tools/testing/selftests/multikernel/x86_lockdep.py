#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Fail-closed live lockdep boundary checks via the existing proc interface."""
import json
import os
from pathlib import Path
import re
import select
import sys
import termios
import time

REQUIRED_CONFIG = frozenset({
    'CONFIG_LOCKDEP=y', 'CONFIG_PROVE_LOCKING=y', 'CONFIG_PROVE_RAW_LOCK_NESTING=y',
    'CONFIG_PROVE_RCU=y', 'CONFIG_PROVE_RCU_LIST=y', 'CONFIG_DEBUG_ATOMIC_SLEEP=y',
    'CONFIG_DEBUG_PREEMPT=y',
})


def decode_record(text):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate live lockdep JSON field: ' + key)
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=unique_fields)
    if not isinstance(value, dict):
        raise ValueError('live lockdep record is not an object')
    return value


def read_debug_locks(path=Path('/proc/lockdep_stats')):
    fields = [line.strip() for line in path.read_text().splitlines()
              if re.match(r'\s*debug_locks\s*:', line)]
    if len(fields) != 1 or not re.fullmatch(r'debug_locks:\s+1', fields[0]):
        raise RuntimeError('live debug_locks missing, malformed or disabled')
    return 1


def child_final(marker, nonce):
    if not re.fullmatch(r'[0-9a-f]{16}', nonce):
        raise RuntimeError('invalid lockdep probe nonce')
    marker('CHILD_LOCKDEP_FINAL', nonce=nonce, debug_locks=read_debug_locks(),
           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def probe_child(fd, pending, nonce):
    """Read child state before stopping it; preserve every intervening byte."""
    if not re.fullmatch(r'[0-9a-f]{16}', nonce):
        raise RuntimeError('invalid lockdep probe nonce')
    command = f'lockdep {nonce}\n'.encode()
    if os.write(fd, command) != len(command):
        raise RuntimeError('short lockdep probe write')
    pending = bytearray(pending)
    captured = len(pending)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        while b'\n' in pending:
            line, _, pending = pending.partition(b'\n')
            text = line.decode(errors='replace').rstrip('\r')
            print(text, flush=True)
            if text.startswith('MK_X86_FAIL '):
                raise RuntimeError('child failure during live lockdep probe')
            if text.startswith('MK_X86_CHILD_LOCKDEP_FINAL '):
                try:
                    value = decode_record(text.partition(' ')[2])
                except ValueError as error:
                    raise RuntimeError('invalid live lockdep reply') from error
                if (value.get('nonce') != nonce
                        or type(value.get('debug_locks')) is not int or value['debug_locks'] != 1):
                    raise RuntimeError('uncorrelated or disabled child lockdep')
                if sys.stdout.isatty():
                    termios.tcdrain(sys.stdout.fileno())
                return pending
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(fd, 8192)
        except BlockingIOError:
            continue
        if not chunk:
            raise RuntimeError('child closed before live lockdep reply')
        pending.extend(chunk)
        captured += len(chunk)
        if captured > 1024 * 1024:
            raise RuntimeError('child diagnostic flood during lockdep probe')
    raise RuntimeError('live child lockdep probe timed out')


def verify_boundaries(trace, begin, end, after, *, terminal=False, before=None):
    """Require four live samples, exact identity, and the intended ordering."""
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': missing or duplicate live lockdep boundary')
            value = decode_record(matches[0][1])
            return matches[0].start(), value
        samples = [one(name) for name in (begin, 'CHILD_ALIVE', 'CHILD_LOCKDEP_FINAL', end)]
        for _, value in samples:
            if type(value.get('debug_locks')) is not int or value['debug_locks'] != 1:
                raise ValueError('missing, malformed or disabled live debug_locks')
        positions = [position for position, _ in samples]
        if positions != sorted(positions):
            raise ValueError('live lockdep boundaries out of order')
        final_at, final = samples[2]
        if (final.get('nonce') != one('PING')[1].get('nonce')
                or final.get('boot_id') != samples[1][1].get('boot_id')):
            raise ValueError('child lockdep identity/nonce mismatch')
        if final_at <= one(after)[0]:
            raise ValueError('child lockdep sampled before tested operation')
        if not terminal and final_at >= trace.find('Instance 1 (native-child) halted, all CPUs confirmed parked'):
            raise ValueError('child lockdep sampled after stop confirmation')
        if before and final_at >= one(before)[0]:
            raise ValueError('child lockdep sampled after drain release/completion')
    except (ValueError, TypeError, KeyError) as error:
        return [str(error)]
    return []
