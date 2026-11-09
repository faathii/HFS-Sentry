#!/usr/bin/env python3
"""NetSentry - Concurrent Port Scanner & OWASP HTTP Header Auditor.

Zero external dependencies (Python 3 standard library only).
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import socket
import ssl
import sys
import time
from typing import Any, Dict, List, Optional
import urllib.request

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443]

PLAINTEXT_RISK_PORTS = {
    21: "FTP (Plaintext credentials & data transmission)",
    23: "Telnet (Unencrypted remote administration - High risk)",
    80: "HTTP (Unencrypted web traffic - MitM risk if no HSTS)",
    110: "POP3 (Plaintext email credentials)",
    143: "IMAP (Plaintext email credentials without STARTTLS)",
}

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
}

OWASP_SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "purpose": "HSTS - Enforces secure HTTPS and prevents SSL stripping",
    },
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "purpose": "CSP - Mitigates XSS and data injection attacks",
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "purpose": "Mitigates Clickjacking by controlling framing permissions",
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "purpose": "Prevents MIME-sniffing attacks (nosniff)",
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "purpose": "Controls sensitive URL parameter leakage in Referer headers",
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "purpose": "Restricts browser feature delegations (camera, mic, geolocation)",
    },
]


def resolve_host(host: str) -> str:
    """Resolve hostname to IPv4 address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{host}': {e}")


def grab_banner(host: str, port: int, timeout: float = 0.8) -> str:
    """Lightweight banner grabbing from an open TCP socket."""
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                data = s.recv(128)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip().split("\r\n")[0]
            except (socket.timeout, socket.error):
                pass
    except Exception:
        pass
    return banner


def scan_single_port(host: str, port: int, timeout: float = 0.6) -> Optional[Dict[str, Any]]:
    """Probe single TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            s.close()
            banner = grab_banner(host, port, timeout=0.8)
            service = SERVICE_NAMES.get(port, "Unknown")
            is_risk = port in PLAINTEXT_RISK_PORTS
            return {
                "port": port,
                "state": "OPEN",
                "service": service,
                "banner": banner,
                "plaintext_risk": is_risk,
                "risk_description": PLAINTEXT_RISK_PORTS.get(port, ""),
            }
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None


def scan_ports(host: str, ports: List[int], workers: int = 20, timeout: float = 0.6) -> List[Dict[str, Any]]:
    """Scan list of ports concurrently."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            res = future.result()
            if res:
                open_ports.append(res)
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def audit_http_headers(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Audit OWASP security headers on web endpoint."""
    protocol = "https" if port in (443, 8443) else "http"
    url = f"{protocol}://{host}" if port in (80, 443) else f"{protocol}://{host}:{port}"

    results = {
        "url": url,
        "protocol": protocol.upper(),
        "status_code": None,
        "headers_audited": {},
        "missing_headers": [],
        "present_headers": [],
        "score_fraction": "0/6",
        "grade": "F",
        "error": None,
    }

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetSentry/1.0 (OWASP Auditor; HFS-Sentry)"},
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if protocol == "https" else None) as resp:
            results["status_code"] = resp.status
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        results["status_code"] = e.code
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        results["error"] = str(e)
        return results

    present_count = 0
    for h in OWASP_SECURITY_HEADERS:
        key = h["key"]
        name = h["name"]
        val = resp_headers.get(key)
        is_present = val is not None
        if is_present:
            present_count += 1
            results["present_headers"].append(name)
        else:
            results["missing_headers"].append(name)

        results["headers_audited"][name] = {
            "present": is_present,
            "value": val,
            "purpose": h["purpose"],
        }

    results["score_fraction"] = f"{present_count}/{len(OWASP_SECURITY_HEADERS)}"
    if present_count >= 5:
        results["grade"] = "A"
    elif present_count >= 3:
        results["grade"] = "B"
    else:
        results["grade"] = "F"

    return results


def run_netsentry(
    target: str,
    ports: Optional[List[int]] = None,
    workers: int = 20,
    timeout: float = 0.6,
    audit_web: bool = True,
) -> Dict[str, Any]:
    """Execute complete NetSentry scan pipeline."""
    if ports is None:
        ports = DEFAULT_PORTS

    start_time = time.time()
    ip = resolve_host(target)

    open_ports = scan_ports(ip, ports, workers=workers, timeout=timeout)
    scan_duration = round(time.time() - start_time, 3)

    web_audit = None
    if audit_web:
        open_port_numbers = [p["port"] for p in open_ports]
        if 443 in open_port_numbers or 8443 in open_port_numbers:
            p = 443 if 443 in open_port_numbers else 8443
            web_audit = audit_http_headers(target, port=p)
        elif 80 in open_port_numbers or 8080 in open_port_numbers:
            p = 80 if 80 in open_port_numbers else 8080
            web_audit = audit_http_headers(target, port=p)

    return {
        "tool": "NetSentry",
        "target": target,
        "ip": ip,
        "scanned_ports_count": len(ports),
        "duration_seconds": scan_duration,
        "open_ports": open_ports,
        "web_header_audit": web_audit,
    }


def print_cli_report(data: Dict[str, Any]) -> None:
    """Print formatted CLI report."""
    print("=" * 72)
    print(f" {bold('[NetSentry] Concurrent Port Scanner & OWASP Header Auditor')}")
    print(f" Target: {cyan(data['target'])} ({data['ip']}) | Ports: {data['scanned_ports_count']} in {data['duration_seconds']}s")
    print("=" * 72)

    print(f"\n--- {bold('[1] Open TCP Ports & Banner Grabbing')} ---")
    if not data["open_ports"]:
        print("  No open ports discovered in target port list.")
    else:
        header = f"  {'PORT':<8} {'SERVICE':<15} {'BANNER':<28} {'SECURITY STATUS'}"
        print(bold(header))
        print("  " + "-" * 68)
        for p in data["open_ports"]:
            banner_preview = (p["banner"][:26] + "..") if len(p["banner"]) > 26 else (p["banner"] or "-")
            alert = red(f"! {p['risk_description']}") if p["plaintext_risk"] else green("OK (Encrypted/Standard)")
            print(f"  {p['port']:<8} {p['service']:<15} {banner_preview:<28} {alert}")

    web_audit = data.get("web_header_audit")
    if web_audit:
        print(f"\n--- {bold('[2] OWASP HTTP Security Headers Audit')} ---")
        if web_audit.get("error"):
            print(f"  {yellow('Notice:')} Web check skipped/failed ({web_audit['error']})")
        else:
            grade_color = green if web_audit["grade"] == "A" else (yellow if web_audit["grade"] == "B" else red)
            print(f"  Endpoint: {cyan(web_audit['url'])} (Status: {web_audit['status_code']})")
            print(f"  Score: {web_audit['score_fraction']} -> GRADE: [{grade_color(bold(web_audit['grade']))}]")
            print("  " + "-" * 68)
            for name, details in web_audit["headers_audited"].items():
                status_tag = green("[PASS]") if details["present"] else red("[FAIL]")
                print(f"  {status_tag:<16} {bold(name):<36} {details['purpose']}")
                if details["present"]:
                    val_snippet = (details['value'][:50] + '...') if len(details['value']) > 50 else details['value']
                    print(f"                  Value: {val_snippet}")

    print("\n" + "=" * 72 + "\n")


@register_tool
class NetSentryTool(BaseTool):
    name = "netsentry"
    description = "Concurrent TCP port scanner, banner grabber & OWASP HTTP security header auditor"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "Network"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("target", help="Target hostname or IPv4 address (e.g. scanme.nmap.org, 127.0.0.1)")
        parser.add_argument(
            "-p", "--ports",
            help="Comma-separated list of ports (e.g. 22,80,443) or range (e.g. 20-100)",
            default=None,
        )
        parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrent worker threads (default: 20)")
        parser.add_argument("--timeout", type=float, default=0.6, help="Connect timeout in seconds (default: 0.6)")
        parser.add_argument("--no-web-audit", action="store_true", help="Skip HTTP/HTTPS security header check")
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        port_list = None
        if args.ports:
            port_list = []
            for part in args.ports.split(","):
                part = part.strip()
                if "-" in part:
                    s, e = map(int, part.split("-"))
                    port_list.extend(range(s, e + 1))
                else:
                    port_list.append(int(part))

        report = run_netsentry(
            target=args.target,
            ports=port_list,
            workers=args.threads,
            timeout=args.timeout,
            audit_web=not args.no_web_audit,
        )

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_cli_report(report)
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=NetSentryTool.description)
    tool = NetSentryTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))

