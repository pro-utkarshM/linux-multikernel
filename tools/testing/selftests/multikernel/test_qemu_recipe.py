# SPDX-License-Identifier: GPL-2.0-only
"""Recipe boundaries only: these are not guest or ring-transport proof."""
import importlib.util
import errno
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recipe', Path(__file__).with_name('qemu-host-init.py'))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class Recipe(unittest.TestCase):
    def test_expected_kernel_errno_not_any_failure(self):
        def rejected():
            raise OSError(errno.EBUSY, 'busy')
        self.assertEqual(recipe.require_errno(rejected, errno.EBUSY), errno.EBUSY)
        with self.assertRaises(AssertionError):
            recipe.require_errno(rejected, errno.EPERM)
        with self.assertRaises(AssertionError):
            recipe.require_errno(lambda: None, errno.EBUSY)

    def test_console_selection_precedes_child_execution(self):
        with patch.object(recipe.os, 'open', return_value=7) as opened, \
                patch.object(recipe.os, 'write', return_value=2) as written:
            self.assertEqual(recipe.connect_console(1), 7)
            opened.assert_called_once()
            written.assert_called_once_with(7, b'1\n')

    def test_drain_collects_late_output_and_detects_child_failure(self):
        received = bytearray()
        with patch.object(recipe.select, 'select', side_effect=[([7], [], []), ([], [], [])]), \
                patch.object(recipe.os, 'read', return_value=b'Rebooting in 1 seconds..\n'):
            recipe.drain_console(7, received)
        self.assertIn(b'Rebooting in 1 seconds', received)
        with patch.object(recipe.select, 'select', return_value=([7], [], [])), \
                patch.object(recipe.os, 'read', return_value=b'MK_CHILD_FAIL late\n'):
            with self.assertRaises(AssertionError):
                recipe.drain_console(7, received)


if __name__ == '__main__':
    unittest.main()
