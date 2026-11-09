"""Unit tests for IntegrityGuard (FIM)."""

import json
import os
import tempfile
import unittest

from sentry.tools.integrityguard import (
    compute_sha256,
    generate_baseline,
    verify_integrity,
)


class TestIntegrityGuard(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.test_dir, "test1.txt")
        self.file2 = os.path.join(self.test_dir, "test2.txt")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("Integrity test line 1")
        with open(self.file2, "w", encoding="utf-8") as f:
            f.write("Integrity test line 2")
        self.baseline_file = os.path.join(self.test_dir, "baseline.json")

    def tearDown(self):
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)

    def test_hash_computation(self):
        h = compute_sha256(self.file1)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_baseline_and_integrity_verification(self):
        generate_baseline([self.file1, self.file2], self.baseline_file)
        self.assertTrue(os.path.isfile(self.baseline_file))

        # Check clean state
        res = verify_integrity(self.baseline_file)
        self.assertFalse(res["tampered"])
        self.assertEqual(res["intact_count"], 2)

        # Alter file 1
        with open(self.file1, "a", encoding="utf-8") as f:
            f.write("TAMPERED DATA")

        res_tampered = verify_integrity(self.baseline_file)
        self.assertTrue(res_tampered["tampered"])
        self.assertEqual(len(res_tampered["modified"]), 1)
        self.assertEqual(res_tampered["modified"][0]["path"], os.path.abspath(self.file1))

        # Delete file 2
        os.remove(self.file2)
        res_deleted = verify_integrity(self.baseline_file)
        self.assertTrue(res_deleted["tampered"])
        self.assertEqual(len(res_deleted["deleted"]), 1)


if __name__ == "__main__":
    unittest.main()
