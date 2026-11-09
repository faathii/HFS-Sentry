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

    def test_run_dnsprobe_mocked(self):
        from unittest.mock import patch
        from sentry.tools.dnsprobe import run_dnsprobe

        mock_spf_dmarc = {
            "spf": {"found": True, "raw": "v=spf1 -all", "status": "PASS", "notes": "Strict"},
            "dmarc": {"found": True, "raw": "v=DMARC1; p=reject", "policy": "reject", "status": "PASS", "notes": "Reject"},
            "mx_records": ["mail.example.com"],
            "overall_email_rating": "HARDENED",
        }
        with patch("sentry.tools.dnsprobe.query_doh") as mock_doh, \
             patch("sentry.tools.dnsprobe.audit_email_security", return_value=mock_spf_dmarc):
            mock_doh.return_value = {
                "AD": True,
                "Answer": [{"data": "93.184.216.34"}]
            }
            res = run_dnsprobe("example.com")
            self.assertEqual(res["domain"], "example.com")
            self.assertTrue(res["dnssec_validated"])
            self.assertIn("A", res["records"])
            self.assertEqual(res["email_security"]["overall_email_rating"], "HARDENED")


if __name__ == "__main__":
    unittest.main()

