"""Unit tests for TrafficSentry."""

import unittest
from sentry.tools.trafficsentry import TrafficSentryTool, _evaluate_socket_risk


class TestTrafficSentry(unittest.TestCase):

    def test_tool_metadata(self):
        tool = TrafficSentryTool()
        self.assertEqual(tool.name, "trafficsentry")
        self.assertEqual(tool.category, "Host & Network")
        self.assertEqual(tool.version, "1.0.0")

    def test_risk_evaluation(self):
        # 0.0.0.0 with Telnet (port 23) should be CRITICAL
        risk, desc = _evaluate_socket_risk("TCP", "0.0.0.0", 23, "LISTENING")
        self.assertEqual(risk, "CRITICAL")
        self.assertIn("Peligro", desc)

        # 0.0.0.0 with MySQL (port 3306) should be HIGH
        risk, desc = _evaluate_socket_risk("TCP", "0.0.0.0", 3306, "LISTENING")
        self.assertEqual(risk, "HIGH")

        # 127.0.0.1 should be CLEAN
        risk, desc = _evaluate_socket_risk("TCP", "127.0.0.1", 8080, "LISTENING")
        self.assertEqual(risk, "CLEAN")


if __name__ == "__main__":
    unittest.main()
