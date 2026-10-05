#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Marker output must drain before a subsequent operation can printk."""
import contextlib
import io
import os
import pty
import termios
import unittest
from unittest import mock

from x86_host_init import marker


class MarkerOrdering(unittest.TestCase):
    def test_marker_is_flushed_and_drained_before_return(self):
        master, slave = pty.openpty()
        os.set_blocking(master, False)
        observed = []
        drain = termios.tcdrain

        def drained(fd):
            drain(fd)
            observed.append(os.read(master, 65536))

        try:
            with os.fdopen(os.dup(slave), 'w') as stream, \
                    contextlib.redirect_stdout(stream), \
                    mock.patch('termios.tcdrain', side_effect=drained):
                marker('TTY_COMPLETE', nonce='1234567890abcdef')
            self.assertEqual(observed, [b'MK_X86_TTY_COMPLETE {"nonce": "1234567890abcdef"}\r\n'])
        finally:
            os.close(slave)
            os.close(master)

    def test_redirected_output_needs_no_terminal(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            marker('TEST', count=1)
        self.assertEqual(stream.getvalue(), 'MK_X86_TEST {"count": 1}\n')


if __name__ == '__main__':
    unittest.main()
