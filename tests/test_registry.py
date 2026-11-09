"""Unit tests for Tool Registry and BaseTool abstraction."""

import argparse
import unittest
from sentry.core.base import BaseTool
from sentry.core.registry import get_tool, get_tool_registry, list_tools, register_tool


class MockSampleTool(BaseTool):
    name = "mocktool"
    description = "A mock tool for testing registration"
    author = "Tester"
    version = "1.0.0"
    category = "Testing"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--test-arg", action="store_true")

    def run(self, args: argparse.Namespace) -> int:
        return 42


class TestRegistry(unittest.TestCase):

    def test_core_tools_registered(self):
        # Ensure all 5 official tools are registered
        reg = get_tool_registry()
        expected = ["netsentry", "logsentinel", "certsentry", "subnetsweep", "integrityguard", "dnsprobe"]
        for tool_name in expected:
            self.assertIn(tool_name, reg, f"Expected {tool_name} to be in registry")
            tool = get_tool(tool_name)
            self.assertIsNotNone(tool)
            self.assertEqual(tool.name, tool_name)

    def test_list_tools_sorted(self):
        tools = list_tools()
        names = [t.name for t in tools]
        self.assertEqual(names, sorted(names))

    def test_dynamic_registration(self):
        register_tool(MockSampleTool)
        self.assertIn("mocktool", get_tool_registry())
        t = get_tool("mocktool")
        self.assertIsNotNone(t)
        self.assertEqual(t.category, "Testing")


if __name__ == "__main__":
    unittest.main()

