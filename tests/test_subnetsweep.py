"""Unit tests for SubnetSweep."""

import unittest
from sentry.tools.subnetsweep import resolve_oui


class TestSubnetSweep(unittest.TestCase):

    def test_oui_lookup(self):
        # Test Raspberry Pi OUI
        self.assertIn("Raspberry Pi", resolve_oui("B8:27:EB:12:34:56"))
        self.assertIn("Raspberry Pi", resolve_oui("dc-a6-32-aa-bb-cc"))

        # Test Cisco OUI
        self.assertIn("Cisco", resolve_oui("00:00:0C:01:02:03"))

        # Test Espressif (ESP32)
        self.assertIn("Espressif", resolve_oui("24:0A:C4:00:11:22"))

        # Test Unknown
        self.assertEqual(resolve_oui("FF:FF:FF:00:00:00"), "Generic / Unregistered Vendor")
        self.assertEqual(resolve_oui(""), "Unknown")


if __name__ == "__main__":
    unittest.main()
