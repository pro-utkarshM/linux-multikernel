#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Additional native kernfs snapshot gate, composed with existing VM verifiers."""
import re
from x86_lockdep import decode_record


def verify_records(held, done, child, spare, removal):
    try:
        before, after = held['gate'], done['gate']
        if (before.get('active') is not True or before.get('point') != 1
                or after.get('active') is not False or after.get('point') != 0
                or before.get('overflow') is not False or after.get('overflow') is not False):
            raise ValueError('missing active controller hold/release or lost observations')
        enters = [e for e in before['events'] if e['point'] == 9 and e['result'] == 1]
        leaves = [e for e in after['events'] if e['point'] == 10]
        if (len(enters) != 1 or len(leaves) != 1
                or enters[0] not in after['events']
                or any(e['point'] == 11 for e in after['events'])
                or leaves[0]['seq'] <= enters[0]['seq']
                or leaves[0]['request'] != enters[0]['request']
                or leaves[0]['result'] != 0 or enters[0]['cpu'] != 0
                or type(done.get('transaction')) is not int or done['transaction'] <= 0
                or done['transaction'] != enters[0]['request'] or done.get('status') != 'applied'):
            raise ValueError('wrong controller transaction, gate expiry or missing release')
        for name in ('root', 'instance'):
            read, retry = held['reads'][name], done['retries'][name]
            if (type(read.get('errno')) is not int or read['errno'] != 11
                    or type(read.get('elapsed_ms')) is not int or not 0 <= read['elapsed_ms'] < 2000
                    or type(retry.get('attempts')) is not int or not 2 <= retry['attempts'] <= 202
                    or type(retry.get('elapsed_ms')) is not int or not 0 <= retry['elapsed_ms'] < 2000):
                raise ValueError('read did not return EAGAIN promptly or retry was unbounded')
        expected_free = sorted(child + spare) if removal else sorted(spare + child[-1:])
        if (done.get('removal') is not removal
                or done.get('root') != dict(cpus=sorted(child + spare), available=expected_free)
                or done.get('instance') != (None if removal else dict(cpus=child[:-1]))
                or done.get('stale_errno') != (19 if removal else 0)):
            raise ValueError('wrong post-writer resources or deactivated descriptor still readable')
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return [str(error)]
    return []


def verify(trace, *, removal=False):
    try:
        def one(name):
            matches = list(re.finditer(r'^MK_X86_' + name + r' (.*)$', trace, re.M))
            if len(matches) != 1:
                raise ValueError(name + ': missing/duplicate snapshot boundary')
            return matches[0].start(), decode_record(matches[0][1])
        groups = one('NESTED_BEGIN')[1]
        nonce = one('PING')[1]['nonce']
        held_at, held = one('SNAPSHOT_HELD')
        done_at, done = one('SNAPSHOT_SETTLED')
        before = 'NESTED_UNLOADED' if removal else 'NESTED_POOL_RETIRED'
        after = 'DESTROY_HELD' if removal else 'ADMISSION_BEGIN'
        after_at = trace.find('MK_X86_' + after + ' ')
        if (held.get('nonce') != nonce or done.get('nonce') != nonce
                or not one(before)[0] < held_at < done_at < after_at):
            raise ValueError('snapshot phase out of order or wrong nonce')
        return verify_records(held, done, groups['child_cpus'], groups['spare_cpus'], removal)
    except (KeyError, TypeError, ValueError) as error:
        return [str(error)]
