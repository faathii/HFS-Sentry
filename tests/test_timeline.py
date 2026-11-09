"""Unit tests for Time-Window Scanning and Process Name Resolution features."""

import os
import unittest
from unittest.mock import MagicMock, patch

from sentry.tools.trafficsentry import audit_sockets_timeline, get_process_name_by_pid
from sentry.tools.subnetsweep import sweep_subnet_timeline
from sentry.tools.logsentinel import watch_log_timeline
from sentry.tools.integrityguard import watch_integrity_timeline
from sentry.tools.netsentry import scan_ports_timeline


class TestTimelineFeatures(unittest.TestCase):
    """Test observation windows and continuous telemetry capabilities."""

    def test_process_name_resolution(self):
        """Current python process should resolve cleanly."""
        current_pid = os.getpid()
        name = get_process_name_by_pid(current_pid)
        self.assertTrue(name.lower().startswith("python") or "pid-" in name.lower())
        self.assertEqual(get_process_name_by_pid(0), "[System Idle]")
        self.assertEqual(get_process_name_by_pid(4), "System")

    def test_trafficsentry_timeline_snapshot(self):
        """Zero duration should execute a single rapid cycle."""
        sockets = audit_sockets_timeline(duration=0.0)
        self.assertIsInstance(sockets, list)
        for s in sockets:
            self.assertIn("timeline_status", s)
            self.assertIn("process_name", s)
            self.assertIn("first_seen", s)

    def test_subnetsweep_timeline_snapshot(self):
        """Sweep timeline should return enriched metadata."""
        with patch("sentry.tools.subnetsweep.sweep_subnet") as mock_sweep:
            mock_sweep.return_value = [
                {"ip": "192.168.1.50", "mac": "00:11:22:33:44:55", "vendor": "Dell", "hostname": "workstation"}
            ]
            hosts = sweep_subnet_timeline("192.168.1.0/24", duration=0.0)
            self.assertEqual(len(hosts), 1)
            self.assertEqual(hosts[0]["status"], "ACTIVO")
            self.assertIn("first_seen", hosts[0])

    def test_logsentinel_watch_timeline(self):
        """Log watcher should tail lines and report incidents."""
        example_log = os.path.join("examples", "sample_auth.log")
        if os.path.isfile(example_log):
            threats = watch_log_timeline(example_log, duration=0.0, ssh_threshold=2)
            self.assertIsInstance(threats, list)
            self.assertGreater(len(threats), 0)

    def test_netsentry_timeline_watchdog(self):
        """Watchdog should compute stability and latency metrics."""
        with patch("sentry.tools.netsentry.scan_ports") as mock_scan:
            mock_scan.return_value = [
                {"port": 80, "latency_ms": 12.5, "banner": "Apache"}
            ]
            ports = scan_ports_timeline("127.0.0.1", ports=[80], duration=0.0)
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports[0]["status"], "ESTABLE")
            self.assertEqual(ports[0]["stability_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()

