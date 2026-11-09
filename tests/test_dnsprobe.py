"""Unit tests for DnsProbe."""

import unittest
from sentry.tools.dnsprobe import DnsProbeTool, audit_email_security


class TestDnsProbe(unittest.TestCase):

    def test_tool_metadata(self):
        tool = DnsProbeTool()
        self.assertEqual(tool.name, "dnsprobe")
        self.assertEqual(tool.category, "DNS & Email")
        self.assertEqual(tool.version, "1.0.0")

    def test_email_security_structure(self):
        # Even on an invalid/dummy domain, structure must be properly formatted
        res = audit_email_security("example-non-existent-domain-12345.xyz")
        self.assertIn("spf", res)
        self.assertIn("dmarc", res)
        self.assertIn("overall_email_rating", res)
        self.assertIn(res["overall_email_rating"], ["HARDENED", "PARTIALLY PROTECTED", "VULNERABLE (Spoofing Risk)"])


if __name__ == "__main__":
    unittest.main()

