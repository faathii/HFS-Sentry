"""Unit tests for NetSentry."""

import unittest
from sentry.tools.netsentry import NetSentryTool, resolve_host


class TestNetSentry(unittest.TestCase):

    def test_tool_metadata(self):
        tool = NetSentryTool()
        self.assertEqual(tool.name, "netsentry")
        self.assertEqual(tool.category, "Network")

    def test_localhost_resolution(self):
        ip = resolve_host("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
