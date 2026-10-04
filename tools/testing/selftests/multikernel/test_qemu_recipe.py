# SPDX-License-Identifier: GPL-2.0-only
"""Recipe boundaries only: these are not guest or ring-transport proof."""
import importlib.util
import errno
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recipe', Path(__file__).with_name('qemu-host-init.py'))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class Recipe(unittest.TestCase):
    def test_overlay_rejection_uses_transaction_status_not_write_errno(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'overlays/tx_1').mkdir(parents=True)
            original_write = Path.write_bytes
            def apply(path, data):
                self.assertEqual(path, base / 'overlays/new')
                tx = base / 'overlays/tx_2'
                tx.mkdir()
                (tx / 'status').write_text('failed\n')
                (tx / 'instance').write_text('/instances\n')
                original_write(tx / 'dtbo', data)
                return len(data)
            with patch.object(recipe.Path, 'write_bytes', apply):
                self.assertEqual(recipe.require_failed_overlay(base, b'dtbo'), 'tx_2')

    def test_probe_setup_reports_the_exact_rejected_command(self):
        with patch.object(recipe.os, 'open', return_value=7) as opened, \
                patch.object(recipe.os, 'write', side_effect=OSError(errno.EINVAL, 'Invalid argument')), \
                patch.object(recipe.os, 'close') as closed:
            with self.assertRaisesRegex(RuntimeError, 'p:mk_copy kimage_load_segment'):
                recipe.register_probe(Path('/trace'), 'p:mk_copy kimage_load_segment')
            opened.assert_called_once_with(Path('/trace/kprobe_events'), recipe.os.O_WRONLY | recipe.os.O_APPEND)
            closed.assert_called_once_with(7)

    def test_probe_setup_does_not_seek_on_tracefs(self):
        command = 'p:mk_start sbi_hsm_hart_start'
        with patch.object(recipe.os, 'open', return_value=7) as opened, \
                patch.object(recipe.os, 'write', return_value=len(command) + 1) as written, \
                patch.object(recipe.os, 'close') as closed, \
                patch.object(recipe.Path, 'open', side_effect=AssertionError('buffered append seeks')):
            recipe.register_probe(Path('/trace'), command)
            opened.assert_called_once_with(Path('/trace/kprobe_events'), recipe.os.O_WRONLY | recipe.os.O_APPEND)
            written.assert_called_once_with(7, (command + '\n').encode())
            closed.assert_called_once_with(7)

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
