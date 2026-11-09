"""Unit tests for Desktop GUI Suite."""

import os
import unittest
import tkinter as tk
from sentry.ui.theme import COLORS, FONTS, apply_suite_theme
from sentry.ui.windows import TOOL_WINDOW_MAP


class TestDesktopUI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
            apply_suite_theme(cls.root)
            cls.has_display = True
        except Exception:
            cls.has_display = False

    @classmethod
    def tearDownClass(cls):
        if cls.has_display:
            try:
                cls.root.destroy()
            except Exception:
                pass

    def test_tool_window_mappings(self):
        expected_tools = ["netsentry", "logsentinel", "certsentry", "subnetsweep", "integrityguard", "dnsprobe", "trafficsentry"]
        for tool_id in expected_tools:
            self.assertIn(tool_id, TOOL_WINDOW_MAP)
            win_cls = TOOL_WINDOW_MAP[tool_id]
            self.assertEqual(win_cls.tool_id, tool_id)
            self.assertTrue(hasattr(win_cls, "tool_title"))
            self.assertTrue(hasattr(win_cls, "icon_filename"))

    def test_window_instantiations(self):
        if not self.has_display:
            self.skipTest("No GUI display environment available")

        for tool_id, win_cls in TOOL_WINDOW_MAP.items():
            win = win_cls(master=self.root)
            self.assertIsNotNone(win)
            self.assertTrue(win.winfo_exists())
            self.assertEqual(win.tool_id, tool_id)
            win.destroy()

    def test_theme_colors(self):
        self.assertIn("bg_dark", COLORS)
        self.assertIn("accent_cyan", COLORS)
        self.assertIn("accent_green", COLORS)
        self.assertIn("accent_red", COLORS)


if __name__ == "__main__":
    unittest.main()

