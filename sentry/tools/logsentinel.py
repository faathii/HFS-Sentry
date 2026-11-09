#!/usr/bin/env python3
"""LogSentinel - Forensic Log Analyzer & Active Intrusion Detection.

Zero external dependencies (Python 3 standard library only).
"""

import argparse
from collections import defaultdict
import datetime
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool

# Regex patterns for SSH brute-force logs
SSH_FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+"),
    re.compile(r"Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"authentication failure;.*rhost=(\d{1,3}(?:\.\d{1,3}){3})"),
]

# Regex patterns for Web servers (Nginx/Apache combined or common log format)
WEB_LOG_PATTERN = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3})\s+-\s+\S+\s+\[(.*?)\]\s+"([A-Z]+)\s+(.*?)\s+HTTP\/[0-9.]+"\s+(\d{3})\s+\d+\s+"(.*?)"\s+"(.*?)"'
)
WEB_SIMPLE_PATTERN = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3}).*?"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+).*?".*?"(.*?)"'
)

MALICIOUS_USER_AGENTS = [
    "nikto",
    "sqlmap",
    "acunetix",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "wpscan",
    "nessus",
    "openvas",
    "zgrab",
    "hydra",
    "burpcollaborator",
]

PATH_TRAVERSAL_INDICATORS = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "/etc/passwd",
    "/etc/shadow",
    "win.ini",
    "boot.ini",
    "/proc/self/environ",
    "/var/log/",
]

WEB_EXPLOIT_INDICATORS = [
    "union select",
    "' or '1'='1",
    "--",
    "<script>",
    "eval(",
    "base64_decode(",
    "/bin/sh",
    "/bin/bash",
    ";cat /etc",
    "|cat /etc",
]


class IncidentCollector:
    """Collects and aggregates suspicious security events per IP."""

    def __init__(self) -> None:
        self.ip_events: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "ssh_failed_count": 0,
                "traversal_count": 0,
                "scanner_detected": set(),
                "exploit_attempts": 0,
                "sample_payloads": set(),
            }
        )

    def record_ssh_failure(self, ip: str) -> None:
        self.ip_events[ip]["ssh_failed_count"] += 1

    def record_web_incident(
        self,
        ip: str,
        traversal: bool = False,
        scanner_name: Optional[str] = None,
        exploit: bool = False,
        payload: Optional[str] = None,
    ) -> None:
        rec = self.ip_events[ip]
        if traversal:
            rec["traversal_count"] += 1
        if scanner_name:
            rec["scanner_detected"].add(scanner_name)
        if exploit:
            rec["exploit_attempts"] += 1
        if payload and len(rec["sample_payloads"]) < 3:
            rec["sample_payloads"].add(payload[:100])


def analyze_log_file(file_path: str) -> IncidentCollector:
    """Parse log file and detect security incidents."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    collector = IncidentCollector()

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            # SSH check
            ssh_matched = False
            for pat in SSH_FAILED_PATTERNS:
                m = pat.search(line_str)
                if m:
                    groups = m.groups()
                    ip = groups[1] if len(groups) > 1 and "." in groups[1] else groups[0]
                    collector.record_ssh_failure(ip)
                    ssh_matched = True
                    break

            if ssh_matched:
                continue

            # Web check
            m_web = WEB_LOG_PATTERN.match(line_str)
            if m_web:
                ip, ts, method, path, status, ref, ua = m_web.groups()
                _inspect_web_line(collector, ip, path, ua)
                continue

            m_simple = WEB_SIMPLE_PATTERN.search(line_str)
            if m_simple:
                ip, path, ua = m_simple.groups()
                _inspect_web_line(collector, ip, path, ua)

    return collector


def _inspect_web_line(collector: IncidentCollector, ip: str, path: str, user_agent: str) -> None:
    path_lower = path.lower()
    ua_lower = user_agent.lower()

    has_traversal = any(ind in path_lower for ind in PATH_TRAVERSAL_INDICATORS)
    detected_scanner = None
    for scanner in MALICIOUS_USER_AGENTS:
        if scanner in ua_lower:
            detected_scanner = scanner
            break
    has_exploit = any(exp in path_lower for exp in WEB_EXPLOIT_INDICATORS)

    if has_traversal or detected_scanner or has_exploit:
        payload = path if (has_traversal or has_exploit) else f"UA:{user_agent}"
        collector.record_web_incident(
            ip=ip,
            traversal=has_traversal,
            scanner_name=detected_scanner,
            exploit=has_exploit,
            payload=payload,
        )


def evaluate_threats(collector: IncidentCollector, ssh_threshold: int = 5) -> List[Dict[str, Any]]:
    """Filter and evaluate identified threats from aggregated events."""
    threats = []
    for ip, data in collector.ip_events.items():
        reasons = []
        severity = "LOW"

        if data["ssh_failed_count"] >= ssh_threshold:
            reasons.append(f"SSH Brute-Force ({data['ssh_failed_count']} failed attempts)")
            severity = "HIGH" if data["ssh_failed_count"] >= 10 else "MEDIUM"

        if data["traversal_count"] > 0:
            reasons.append(f"Path Traversal Probe ({data['traversal_count']} requests)")
            severity = "HIGH"

        if data["scanner_detected"]:
            scanners = ", ".join(sorted(data["scanner_detected"]))
            reasons.append(f"Automated Vulnerability Scanner ({scanners})")
            severity = "HIGH"

        if data["exploit_attempts"] > 0:
            reasons.append(f"SQLi/RCE Exploit Attempt ({data['exploit_attempts']} requests)")
            severity = "CRITICAL"

        if reasons:
            threats.append({
                "ip": ip,
                "severity": severity,
                "reasons": reasons,
                "ssh_failed_count": data["ssh_failed_count"],
                "traversal_count": data["traversal_count"],
                "scanner_detected": list(data["scanner_detected"]),
                "exploit_attempts": data["exploit_attempts"],
                "sample_payloads": list(data["sample_payloads"]),
            })

    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats.sort(key=lambda x: (priority.get(x["severity"], 4), -x["ssh_failed_count"], -x["traversal_count"]))
    return threats


def _is_stopped(stop_check: Optional[Any]) -> bool:
    if stop_check is None:
        return False
    if hasattr(stop_check, "is_set"):
        return stop_check.is_set()
    if callable(stop_check):
        return stop_check()
    return bool(stop_check)


def watch_log_timeline(
    file_path: str,
    duration: float = 30.0,
    ssh_threshold: int = 5,
    poll_interval: float = 0.5,
    progress_callback: Optional[Callable[[List[Dict[str, Any]], float, int], None]] = None,
    stop_check: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Live stream and analyze log entries in real-time over a time window (e.g. 30 seconds).

    Tails incoming log lines appended to `file_path` and correlates emerging threats dynamically.
    """
    collector = IncidentCollector()
    total_lines = 0

    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        # First read existing content
        for line in f:
            if _is_stopped(stop_check):
                break
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            matched_ssh = False
            for pat in SSH_FAILED_PATTERNS:
                m = pat.search(line)
                if m:
                    ip = m.group(m.lastindex)
                    collector.record_ssh_failure(ip)
                    matched_ssh = True
                    break

            if not matched_ssh:
                m_web = WEB_LOG_PATTERN.match(line)
                if m_web:
                    ip = m_web.group(1)
                    path = m_web.group(4)
                    ua = m_web.group(7)
                    _inspect_web_line(collector, ip, path, ua)
                else:
                    m_simple = WEB_SIMPLE_PATTERN.search(line)
                    if m_simple:
                        ip, path, ua = m_simple.groups()
                        _inspect_web_line(collector, ip, path, ua)

        # Notify initial state
        initial_threats = evaluate_threats(collector, ssh_threshold)
        if progress_callback:
            progress_callback(initial_threats, duration, total_lines)

        if duration <= 0 or _is_stopped(stop_check):
            return initial_threats

        start_time = time.time()
        end_time = start_time + duration

        while True:
            now = time.time()
            remaining = max(0.0, end_time - now) if duration < 100000 else 999999.0

            if _is_stopped(stop_check):
                break

            line = f.readline()
            if line:
                total_lines += 1
                line = line.strip()
                if line:
                    matched_ssh = False
                    for pat in SSH_FAILED_PATTERNS:
                        m = pat.search(line)
                        if m:
                            ip = m.group(m.lastindex)
                            collector.record_ssh_failure(ip)
                            matched_ssh = True
                            break

                    if not matched_ssh:
                        m_web = WEB_LOG_PATTERN.match(line)
                        if m_web:
                            ip = m_web.group(1)
                            path = m_web.group(4)
                            ua = m_web.group(7)
                            _inspect_web_line(collector, ip, path, ua)
                        else:
                            m_simple = WEB_SIMPLE_PATTERN.search(line)
                            if m_simple:
                                ip, path, ua = m_simple.groups()
                                _inspect_web_line(collector, ip, path, ua)

                    current_threats = evaluate_threats(collector, ssh_threshold)
                    if progress_callback:
                        progress_callback(current_threats, remaining, total_lines)
            else:
                if progress_callback:
                    current_threats = evaluate_threats(collector, ssh_threshold)
                    progress_callback(current_threats, remaining, total_lines)
                if hasattr(stop_check, "wait"):
                    if stop_check.wait(timeout=poll_interval):
                        break
                else:
                    time.sleep(poll_interval)

            if _is_stopped(stop_check):
                break

            if duration < 100000 and now >= end_time:
                break

    return evaluate_threats(collector, ssh_threshold)


def generate_block_script(threats: List[Dict[str, Any]], output_file: str = "block_threats.sh") -> str:
    """Generate executable Bash script with UFW and iptables rules."""
    lines = [
        "#!/usr/bin/env bash",
        "# -------------------------------------------------------------",
        "# LogSentinel - Automated Incident Response & Firewall Rules",
        f"# Total threats flagged: {len(threats)}",
        "# Generated automatically by HFS-Sentry Suite",
        "# -------------------------------------------------------------",
        "",
        "set -euo pipefail",
        "",
        "echo '[+] Applying active firewall countermeasures...'",
        "",
    ]

    for t in threats:
        ip = t["ip"]
        comment = "; ".join(t["reasons"]).replace("'", "")
        lines.append(f"# Threat Severity: {t['severity']} | IP: {ip}")
        lines.append(f"if command -v ufw >/dev/null 2>&1; then")
        lines.append(f"    sudo ufw deny from {ip} to any comment 'LogSentinel: {comment}'")
        lines.append(f"fi")
        lines.append(f"if command -v iptables >/dev/null 2>&1; then")
        lines.append(f"    sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null || sudo iptables -A INPUT -s {ip} -j DROP")
        lines.append(f"fi")
        lines.append("")

    lines.append("echo '[✔] All defensive firewall rules configured successfully.'")
    lines.append("")

    content = "\n".join(lines)
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    return os.path.abspath(output_file)


def print_cli_report(threats: List[Dict[str, Any]], log_file: str, block_script: Optional[str] = None) -> None:
    """Display structured incident analysis report."""
    print("=" * 76)
    print(f" {bold('[LogSentinel] Forensic Log Analyzer & Active Threat Detection')}")
    print(f" Source: {cyan(log_file)} | Identified Threats: {len(threats)}")
    print("=" * 76)

    if not threats:
        print(f"\n  {green('[✔] Clean bill of health:')} No intrusion patterns detected exceeding thresholds.\n")
        return

    print(f"\n  {'SEVERITY':<12} {'OFFENDER IP':<18} {'DETECTED ATTACK VECTORS'}")
    print("  " + "-" * 72)
    for t in threats:
        sev = t["severity"]
        sev_color = red if sev in ("CRITICAL", "HIGH") else yellow
        reasons_str = " | ".join(t["reasons"])
        print(f"  [{sev_color(bold(sev)):<20}] {bold(t['ip']):<18} {reasons_str}")
        if t["sample_payloads"]:
            payload_str = t["sample_payloads"][0]
            if len(payload_str) > 60:
                payload_str = payload_str[:57] + "..."
            print(f"               └── Sample: {payload_str}")

    if block_script:
        print("\n" + "-" * 76)
        print(f"  {green('[+] Active Countermeasure Script Generated:')}")
        print(f"      -> {cyan(block_script)}")
        print("      To apply rules on host: bash block_threats.sh")
    print("=" * 76 + "\n")


@register_tool
class LogSentinelTool(BaseTool):
    name = "logsentinel"
    description = "Forensic log analyzer, intrusion detection & automated firewall rule generator"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "Forensic"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("log_file", help="Path to auth.log, secure, or Nginx/Apache access.log")
        parser.add_argument(
            "--threshold",
            type=int,
            default=5,
            help="Failed SSH authentication threshold (default: 5)",
        )
        parser.add_argument(
            "-o", "--output-script",
            default="block_threats.sh",
            help="Path for generated defense script (default: block_threats.sh)",
        )
        parser.add_argument("--no-script", action="store_true", help="Do not generate countermeasure bash script")
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        collector = analyze_log_file(args.log_file)
        threats = evaluate_threats(collector, ssh_threshold=args.threshold)

        script_path = None
        if threats and not args.no_script:
            script_path = generate_block_script(threats, output_file=args.output_script)

        if args.json:
            result = {
                "tool": "LogSentinel",
                "log_file": args.log_file,
                "threat_count": len(threats),
                "threats": threats,
                "block_script": script_path,
            }
            print(json.dumps(result, indent=2))
        else:
            print_cli_report(threats, args.log_file, script_path)
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=LogSentinelTool.description)
    tool = LogSentinelTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))

