#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded /dev/kmsg readback for the intentional MKTTY capture gap."""
import os
import re

MAX_LOG = 8 * 1024 * 1024
DIAGNOSTIC = re.compile(rb'WARNING:|BUG:|Oops:|Kernel panic - not syncing:'
                        rb'|general protection fault|detected (?:expedited )?stalls'
                        rb'|watchdog:.*lockup|rcu:.*(?:self-detected stall|kthread starved)', re.I)


def end_message(nonce):
    if not re.fullmatch(r'[0-9a-f]{16}', nonce):
        raise ValueError('invalid kernel-log nonce')
    return ('MKTTY_LOG_END_' + nonce).encode()


def record_message(record, expected):
    header, separator, message = record.partition(b';')
    fields = header.split(b',')
    if (not separator or len(fields) != 4 or not record.endswith(b'\n')
            or any(not field.isdigit() for field in fields[:3])
            or int(fields[1]) != expected):
        raise ValueError('malformed, missing, duplicate or overwritten kernel-log record')
    return message.split(b'\n', 1)[0]


def read_records(nonce):
    """Read from sequence zero through our end marker; overrun is fatal."""
    end = end_message(nonce)
    reader = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
    try:
        writer = os.open('/dev/kmsg', os.O_WRONLY)
        try:
            # Finalize this printk record before the nonblocking readback.
            message = b'<6>' + end + b'\n'
            if os.write(writer, message) != len(message):
                raise RuntimeError('short kernel-log end-marker write')
        finally:
            os.close(writer)
        records, size = [], 0
        while size <= MAX_LOG:
            record = os.read(reader, 65536)  # EPIPE/EAGAIN propagate; never hide loss.
            message = record_message(record, len(records))
            size += len(record) + 4
            if size > MAX_LOG:
                break
            records.append(record)
            if message == end:
                return records
        raise RuntimeError('retained kernel log exceeds bound')
    finally:
        os.close(reader)


def validate_blob(blob, nonce, count):
    if not blob or len(blob) > MAX_LOG or type(count) is not int or count <= 0:
        raise ValueError('invalid retained-log size/count')
    offset, records, last = 0, 0, None
    end = end_message(nonce)
    while offset < len(blob):
        if offset + 4 > len(blob):
            raise ValueError('truncated kernel-log length')
        size = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4
        if not size or size > 65536 or offset + size > len(blob):
            raise ValueError('truncated or oversized kernel-log record')
        record = blob[offset:offset + size]
        last = record_message(record, records)
        if DIAGNOSTIC.search(record):
            raise ValueError('kernel diagnostic in retained child log')
        offset += size
        records += 1
        if last == end and offset != len(blob):
            raise ValueError('records follow retained-log end marker')
    if records != count or last != end:
        raise ValueError('missing retained-log end marker or wrong record count')
