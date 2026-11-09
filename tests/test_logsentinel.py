"""Unit tests for LogSentinel."""

import os
import tempfile
import unittest

from sentry.tools.logsentinel import (
    analyze_log_file,
    evaluate_threats,
    generate_block_script,
)


class TestLogSentinel(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        # Write SSH failures
        for _ in range(6):
            self.temp_file.write(
                "Nov 9 10:00:00 server sshd[100]: Failed password for invalid user admin from 198.51.100.42 port 50000 ssh2\n"
            )
        # Write Web attacks
        self.temp_file.write(
            '203.0.113.15 - - [09/Nov/2026:10:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 100 "-" "curl/7.68"\n'
        )
        self.temp_file.write(
            '198.51.100.99 - - [09/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "sqlmap/1.5"\n'
        )
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_detection_and_evaluation(self):
        collector = analyze_log_file(self.temp_file.name)
        threats = evaluate_threats(collector, ssh_threshold=5)

        ips = {t["ip"] for t in threats}
        self.assertIn("198.51.100.42", ips)
        self.assertIn("203.0.113.15", ips)
        self.assertIn("198.51.100.99", ips)

    def test_block_script_generation(self):
        collector = analyze_log_file(self.temp_file.name)
        threats = evaluate_threats(collector, ssh_threshold=5)

        script_path = tempfile.mktemp(suffix=".sh")
        try:
            generate_block_script(threats, output_file=script_path)
            self.assertTrue(os.path.isfile(script_path))
            with open(script_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("ufw deny from 198.51.100.42", content)
            self.assertIn("iptables -A INPUT -s 198.51.100.42 -j DROP", content)
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)


if __name__ == "__main__":
    unittest.main()
