"""Unit tests for CertSentry."""

import unittest
from sentry.tools.certsentry import CertSentryTool


class TestCertSentry(unittest.TestCase):

    def test_tool_metadata(self):
        tool = CertSentryTool()
        self.assertEqual(tool.name, "certsentry")
        self.assertEqual(tool.category, "Crypto")
        self.assertEqual(tool.version, "1.0.0")


if __name__ == "__main__":
    unittest.main()

