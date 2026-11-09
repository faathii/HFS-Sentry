"""Unit tests for HTML Executive Report Generator."""

import unittest
from sentry.core.report import generate_html_report


class TestReportGenerator(unittest.TestCase):

    def test_generate_html_report(self):
        sample_data = {
            "tool": "NetSentry",
            "target": "example.com",
            "ip": "93.184.216.34",
            "elapsed_seconds": 0.45,
            "open_ports": [
                {"port": 80, "service": "HTTP", "risk": "MitM Risk", "state": "OPEN"},
                {"port": 443, "service": "HTTPS", "risk": "Clean", "state": "OPEN"},
            ],
        }

        html = generate_html_report(sample_data, title="Prueba de Informe")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Prueba de Informe", html)
        self.assertIn("example.com", html)
        self.assertIn("93.184.216.34", html)
        self.assertIn("Open Ports (2 entries)", html)
        self.assertIn("HTTP", html)
        self.assertIn("HTTPS", html)


if __name__ == "__main__":
    unittest.main()

