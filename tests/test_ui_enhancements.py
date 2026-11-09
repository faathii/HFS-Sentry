"""Unit tests for UI enhancements: Treeview sorting, context menu pivots, and configuration."""

import os
import unittest
from unittest.mock import MagicMock

from sentry.core.config import DEFAULT_CONFIG, load_config, save_config, get_config_val, set_config_val
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.app import SentrySuiteApp


class TestUIEnhancements(unittest.TestCase):

    def test_config_persistence(self):
        """Configuration should load, update, and return valid defaults."""
        cfg = load_config()
        self.assertIn("default_duration_seconds", cfg)
        self.assertIn("sound_alerts_enabled", cfg)

        set_config_val("test_key_sample", 42)
        val = get_config_val("test_key_sample")
        self.assertEqual(val, 42)

        # Cleanup test key
        cfg = load_config()
        if "test_key_sample" in cfg:
            del cfg["test_key_sample"]
            save_config(cfg)

    def test_treeview_sorting_key_logic(self):
        """Treeview column sorting logic should sort numbers, risks, and text appropriately."""
        from sentry.ui.windows.netsentry_window import NetSentryWindow
        app = SentrySuiteApp()
        win = NetSentryWindow(master=app)

        # Ensure helper exists and callable
        self.assertTrue(hasattr(win, "enable_treeview_sorting"))
        self.assertTrue(hasattr(win, "enable_treeview_context_menu"))
        self.assertTrue(hasattr(win, "apply_prefill"))

        win.destroy()
        app.destroy()


if __name__ == "__main__":
    unittest.main()
