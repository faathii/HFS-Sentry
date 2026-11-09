"""Unit tests for CertSentry."""

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from sentry.tools.certsentry import CertSentryTool, inspect_certificate


class TestCertSentry(unittest.TestCase):

    def test_tool_metadata(self):
        tool = CertSentryTool()
        self.assertEqual(tool.name, "certsentry")
        self.assertEqual(tool.category, "Crypto")
        self.assertEqual(tool.version, "1.0.0")

    @patch("sentry.tools.certsentry._test_legacy_protocols", return_value=False)
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_inspect_certificate_success(self, mock_conn, mock_ssl_ctx, mock_legacy):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "test.example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "subjectAltName": (("DNS", "test.example.com"), ("DNS", "www.test.example.com")),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "serialNumber": "1234567890ABCDEF",
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"

        res = inspect_certificate("test.example.com", port=443, timeout=1.0)
        self.assertEqual(res["host"], "test.example.com")
        self.assertEqual(res["status"], "HEALTHY")
        self.assertEqual(res["subject_cn"], "test.example.com")
        self.assertEqual(res["issuer_org"], "Test CA")
        self.assertEqual(res["negotiated_protocol"], "TLSv1.3")
        self.assertFalse(res["legacy_tls_detected"])

    @patch("sentry.tools.certsentry._test_legacy_protocols", return_value=False)
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_inspect_certificate_none_cert(self, mock_conn, mock_ssl_ctx, mock_legacy):
        """Should gracefully handle when getpeercert returns None/empty without crashing."""
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssock.getpeercert.return_value = None
        mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
        mock_ssock.version.return_value = "TLSv1.2"

        res = inspect_certificate("selfsigned.local", port=443, timeout=1.0)
        self.assertEqual(res["status"], "UNKNOWN")
        self.assertEqual(res["subject_cn"], "selfsigned.local")
        self.assertEqual(res["issuer_org"], "Unknown")


if __name__ == "__main__":
    unittest.main()

