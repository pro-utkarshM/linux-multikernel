#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real pipe reads: late child diagnostics cannot disappear before unload."""
import contextlib
import io
import os
import unittest
import x86_host_init as host


class StoppedCapture(unittest.TestCase):
    def test_late_complete_and_incomplete_console_records(self):
        self.assertTrue(callable(getattr(host, 'capture_stopped_child', None)), 'stopped-child drain missing')
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
        try:
            os.write(write_fd, b'WARNING: late child diagnostic\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                host.capture_stopped_child(read_fd, bytearray(), '1234567890abcdef', seconds=0.02)
            self.assertIn('WARNING: late child diagnostic', output.getvalue())
            self.assertIn('MK_X86_CHILD_CAPTURED ', output.getvalue())
            os.write(write_fd, b'partial child diagnostic')
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
                host.capture_stopped_child(read_fd, bytearray(), '1234567890abcdef', seconds=0.02)
            self.assertNotIn('MK_X86_CHILD_CAPTURED ', output.getvalue())
        finally:
            os.close(read_fd)
            os.close(write_fd)


if __name__ == '__main__':
    unittest.main()
