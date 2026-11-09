"""Unit tests for Quick Audit engine."""

import unittest
from sentry.core.quick_audit import run_system_quick_audit


class TestQuickAudit(unittest.TestCase):

    def test_quick_audit_structure(self):
        res = run_system_quick_audit()
        self.assertIn("security_score", res)
        self.assertIn("grade", res)
        self.assertIn("grade_label", res)
        self.assertIn("checks", res)
        self.assertGreaterEqual(res["security_score"], 0)
        self.assertLessEqual(res["security_score"], 100)
        self.assertIn(res["grade"], ["A", "B", "F"])
        self.assertGreater(len(res["checks"]), 0)


if __name__ == "__main__":
    unittest.main()
