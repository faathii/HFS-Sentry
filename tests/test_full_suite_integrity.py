"""Comprehensive full suite integrity and edge-case unit test suite for HFS-Sentry."""

import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from sentry.core.config import DEFAULT_CONFIG, load_config, save_config, get_config_val, set_config_val
from sentry.core.quick_audit import run_system_quick_audit
from sentry.core.registry import list_tools, get_tool_registry
from sentry.tools.netsentry import scan_single_port, PLAINTEXT_RISK_PORTS
from sentry.tools.integrityguard import verify_integrity, generate_baseline, compute_sha256
from sentry.tools.subnetsweep import resolve_oui, scan_single_host
from sentry.tools.logsentinel import IncidentCollector, evaluate_threats
from sentry.ui.app import SentrySuiteApp
from sentry.ui.windows.netsentry_window import NetSentryWindow
from sentry.ui.windows.subnetsweep_window import SubnetSweepWindow
from sentry.ui.windows.trafficsentry_window import TrafficSentryWindow
from sentry.ui.windows.logsentinel_window import LogSentinelWindow
from sentry.ui.windows.integrityguard_window import IntegrityGuardWindow
from sentry.ui.windows.certsentry_window import CertSentryWindow
from sentry.ui.windows.dnsprobe_window import DnsProbeWindow


class TestFullSuiteIntegrity(unittest.TestCase):
    """Deep validation of edge cases, fail-safes and GUI reliability."""

    def test_config_corrupt_file_handling(self):
        """Corrupt config file must safely fallback to default without crashing."""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("INVALID_JSON_CORRUPT_DATA{{{")
            tmp_path = f.name

        with patch("sentry.core.config.CONFIG_FILE", tmp_path):
            cfg = load_config()
            self.assertEqual(cfg["default_duration_seconds"], DEFAULT_CONFIG["default_duration_seconds"])
            self.assertEqual(cfg["sound_alerts_enabled"], DEFAULT_CONFIG["sound_alerts_enabled"])

        try:
            os.remove(tmp_path)
        except Exception:
            pass

    def test_netsentry_scan_single_port_latency(self):
        """scan_single_port should return latency_ms when port is open."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0
            mock_sock_cls.return_value = mock_sock

            with patch("sentry.tools.netsentry.grab_banner", return_value="TestBanner"):
                res = scan_single_port("127.0.0.1", 80, timeout=0.1)
                self.assertIsNotNone(res)
                self.assertIn("latency_ms", res)
                self.assertEqual(res["port"], 80)
                self.assertEqual(res["banner"], "TestBanner")

    def test_integrityguard_dict_and_string_polymorphism(self):
        """verify_integrity must accept both file paths and dictionary objects."""
        # 1. Test dict input
        baseline_dict = {
            "generated_at": "2026-01-01T00:00:00Z",
            "files": {
                os.path.abspath(__file__): {
                    "path": os.path.abspath(__file__),
                    "sha256": compute_sha256(os.path.abspath(__file__)),
                    "size_bytes": os.path.getsize(os.path.abspath(__file__)),
                }
            }
        }
        res_dict = verify_integrity(baseline_dict)
        self.assertFalse(res_dict["tampered"])
        self.assertEqual(res_dict["intact_count"], 1)

        # 2. Test string path input
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(baseline_dict, f)
            tmp_path = f.name

        res_path = verify_integrity(tmp_path)
        self.assertFalse(res_path["tampered"])
        self.assertEqual(res_path["intact_count"], 1)

        # 3. Test invalid type
        with self.assertRaises(TypeError):
            verify_integrity(12345)

        try:
            os.remove(tmp_path)
        except Exception:
            pass

    def test_logsentinel_threat_evaluation_priorities(self):
        """Threat evaluation must sort by priority: CRITICAL > HIGH > MEDIUM > LOW."""
        collector = IncidentCollector()
        collector.record_ssh_failure("192.168.1.10")
        collector.record_ssh_failure("192.168.1.10")
        collector.record_ssh_failure("192.168.1.10")
        collector.record_ssh_failure("192.168.1.10")
        collector.record_ssh_failure("192.168.1.10")  # 5 fails -> MEDIUM

        collector.record_web_incident("10.0.0.5", exploit=True, payload="union select 1")  # CRITICAL

        threats = evaluate_threats(collector, ssh_threshold=5)
        self.assertEqual(len(threats), 2)
        self.assertEqual(threats[0]["ip"], "10.0.0.5")
        self.assertEqual(threats[0]["severity"], "CRITICAL")
        self.assertEqual(threats[1]["ip"], "192.168.1.10")
        self.assertEqual(threats[1]["severity"], "MEDIUM")

    def test_all_windows_prefill_contract(self):
        """Every tool window must support apply_prefill without raising exceptions."""
        app = SentrySuiteApp()
        windows = [
            NetSentryWindow(master=app),
            SubnetSweepWindow(master=app),
            TrafficSentryWindow(master=app),
            LogSentinelWindow(master=app),
            IntegrityGuardWindow(master=app),
            CertSentryWindow(master=app),
            DnsProbeWindow(master=app),
        ]

        test_inputs = {
            "netsentry": "192.168.1.55",
            "subnetsweep": "192.168.1.55",
            "trafficsentry": "192.168.1.55",
            "logsentinel": "192.168.1.55",
            "integrityguard": os.path.abspath(__file__),
            "certsentry": "google.com:443",
            "dnsprobe": "cloudflare.com",
        }

        for win in windows:
            self.assertTrue(hasattr(win, "apply_prefill"))
            target = test_inputs.get(win.tool_id, "127.0.0.1")
            win.apply_prefill(target)
            win.destroy()

        app.destroy()

    def test_trafficsentry_ipv6_bracket_parsing(self):
        """TrafficSentry must correctly identify public and localhost IPv6 addresses with brackets."""
        from sentry.tools.trafficsentry import _evaluate_socket_risk

        # Public exposed MySQL on all IPv6 interfaces with brackets
        risk_mysql, desc_mysql = _evaluate_socket_risk("TCP", "[::]", 3306, "LISTENING")
        self.assertEqual(risk_mysql, "HIGH")

        # Public exposed Redis on all IPv4 interfaces
        risk_redis, desc_redis = _evaluate_socket_risk("TCP", "0.0.0.0", 6379, "LISTENING")
        self.assertEqual(risk_redis, "CRITICAL")

        # Localhost IPv6 with brackets
        risk_local6, desc_local6 = _evaluate_socket_risk("TCP", "[::1]", 8080, "LISTENING")
        self.assertEqual(risk_local6, "CLEAN")

        # Localhost IPv4
        risk_local4, desc_local4 = _evaluate_socket_risk("TCP", "127.0.0.1", 8080, "LISTENING")
        self.assertEqual(risk_local4, "CLEAN")

    def test_subnetsweep_large_subnet_guard(self):
        """SubnetSweep should reject /8 or /12 networks exceeding 65,536 hosts to prevent OOM."""
        from sentry.tools.subnetsweep import sweep_subnet
        with self.assertRaises(ValueError):
            sweep_subnet("10.0.0.0/8")

    def test_cli_parser_all_tools(self):
        """CLI parser must parse valid arguments for all registered tools without failing."""
        from sentry.cli import build_parser
        parser = build_parser()

        # NetSentry
        args_ns = parser.parse_args(["netsentry", "127.0.0.1", "-p", "80,443"])
        self.assertEqual(args_ns.target, "127.0.0.1")
        self.assertEqual(args_ns.ports, "80,443")

        # TrafficSentry
        args_ts = parser.parse_args(["trafficsentry", "-l", "-d", "10.0"])
        self.assertTrue(args_ts.listening_only)
        self.assertEqual(args_ts.duration, 10.0)

        # CertSentry
        args_cs = parser.parse_args(["certsentry", "google.com", "-p", "443"])
        self.assertEqual(args_cs.host, "google.com")
        self.assertEqual(args_cs.port, 443)

        # DnsProbe
        args_dp = parser.parse_args(["dnsprobe", "github.com"])
        self.assertEqual(args_dp.domain, "github.com")

        # SubnetSweep
        args_ss = parser.parse_args(["subnetsweep", "192.168.1.0/24"])
        self.assertEqual(args_ss.cidr, "192.168.1.0/24")

        # IntegrityGuard
        args_ig = parser.parse_args(["integrityguard", "--check", "-b", "sentry_baseline.json"])
        self.assertTrue(args_ig.check)

        # LogSentinel
        args_ls = parser.parse_args(["logsentinel", "sample.log", "--threshold", "3"])
        self.assertEqual(args_ls.log_file, "sample.log")
        self.assertEqual(args_ls.threshold, 3)

    def test_notify_user_thread_safety(self):
        """Notification engine must handle thread execution without raising exceptions."""
        from sentry.ui.notifications import notify_user, play_audio_cue
        # Should not raise exception even when headless or without Tkinter root
        notify_user("Test Title", "Test Message", level="info")
        play_audio_cue("info")
        play_audio_cue("critical")
        play_audio_cue("warning")


if __name__ == "__main__":
    unittest.main()
