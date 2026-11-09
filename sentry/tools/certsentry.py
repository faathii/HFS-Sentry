#!/usr/bin/env python3
"""CertSentry - SSL/TLS Certificate Expiration Inspector & Cryptographic Auditor.

Zero external dependencies (Python 3 standard library only).
"""

import argparse
from datetime import datetime, timezone
import json
import socket
import ssl
import sys
from typing import Any, Dict, List, Optional, Tuple

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool


def inspect_certificate(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Retrieve and parse SSL/TLS certificate details using pure standard library ssl."""
    context = ssl.create_default_context()
    # Allow fetching cert even if expired/self-signed for forensic audit
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    start_ts = datetime.now(timezone.utc)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            tls_version = ssock.version()

    # If getpeercert() with CERT_NONE returned empty dict, attempt with CERT_OPTIONAL/REQUIRED
    if not cert:
        try:
            strict_ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with strict_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except Exception:
            pass

    # Extract Subject Common Name
    subject = {}
    for item in cert.get("subject", ()):
        for k, v in item:
            subject[k] = v

    # Extract Issuer
    issuer = {}
    for item in cert.get("issuer", ()):
        for k, v in item:
            issuer[k] = v

    # Extract SANs (Subject Alternative Names)
    sans = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]

    # Extract dates
    not_before_raw = cert.get("notBefore", "")
    not_after_raw = cert.get("notAfter", "")

    not_after_dt = None
    days_left = None
    status = "UNKNOWN"

    date_format = "%b %d %H:%M:%S %Y %Z"
    if not_after_raw:
        try:
            not_after_dt = datetime.strptime(not_after_raw, date_format).replace(tzinfo=timezone.utc)
            delta = not_after_dt - start_ts
            days_left = delta.days
            if days_left < 0:
                status = "EXPIRED"
            elif days_left <= 7:
                status = "CRITICAL"  # <= 7 days
            elif days_left <= 15:
                status = "WARNING"   # <= 15 days
            elif days_left <= 30:
                status = "NOTICE"    # <= 30 days
            else:
                status = "HEALTHY"
        except Exception:
            pass

    # Check for legacy protocol support (TLS 1.0 / 1.1)
    legacy_protocol_supported = _test_legacy_protocols(host, port, timeout=2.0)

    return {
        "host": host,
        "port": port,
        "status": status,
        "days_remaining": days_left,
        "valid_from": not_before_raw,
        "valid_until": not_after_raw,
        "subject_cn": subject.get("commonName", host),
        "issuer_org": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
        "sans_count": len(sans),
        "sans": sans[:10],
        "serial_number": cert.get("serialNumber", "N/A"),
        "negotiated_protocol": tls_version,
        "negotiated_cipher": cipher[0] if cipher else "Unknown",
        "cipher_bits": cipher[2] if cipher else "Unknown",
        "legacy_tls_detected": legacy_protocol_supported,
    }


def _test_legacy_protocols(host: str, port: int, timeout: float = 1.5) -> bool:
    """Test if server accepts obsolete TLS 1.0 or TLS 1.1 handshakes."""
    for proto_attr in ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"):
        if hasattr(ssl, proto_attr):
            try:
                ctx = ssl.SSLContext(getattr(ssl, proto_attr))
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return True
            except Exception:
                pass
    return False


def print_cli_report(data: Dict[str, Any]) -> None:
    """Print formatted CertSentry audit report."""
    print("=" * 74)
    print(f" {bold('[CertSentry] SSL/TLS Certificate Expiration & Cryptographic Inspector')}")
    print(f" Target: {cyan(data['host'])}:{data['port']}")
    print("=" * 74)

    status = data["status"]
    if status == "HEALTHY":
        stat_colored = green(bold(f"[HEALTHY] ({data['days_remaining']} days remaining)"))
    elif status in ("NOTICE", "WARNING"):
        stat_colored = yellow(bold(f"[{status}] Expiring in {data['days_remaining']} days!"))
    elif status == "CRITICAL":
        stat_colored = red(bold(f"[CRITICAL] Expiring in {data['days_remaining']} days! Immediate action required."))
    elif status == "EXPIRED":
        stat_colored = red(bold(f"[EXPIRED] Certificate expired {abs(data['days_remaining'])} days ago!"))
    else:
        stat_colored = yellow(status)

    print(f"\n  Certificate Health:     {stat_colored}")
    print(f"  Valid Until:            {data['valid_until']} (UTC)")
    print(f"  Valid From:             {data['valid_from']}")
    print(f"  Common Name (CN):       {bold(data['subject_cn'])}")
    print(f"  Issuer (CA):            {cyan(data['issuer_org'])}")
    print(f"  Serial Number:          {data['serial_number']}")
    print(f"  SANs ({data['sans_count']}):              {', '.join(data['sans'][:4])}{' ...' if data['sans_count'] > 4 else ''}")

    print(f"\n--- {bold('Cryptographic Negotiation')} ---")
    print(f"  Negotiated Protocol:    {green(data['negotiated_protocol'])}")
    print(f"  Negotiated Cipher:      {cyan(data['negotiated_cipher'])} ({data['cipher_bits']} bits)")

    if data["legacy_tls_detected"]:
        print(f"  Legacy TLS 1.0/1.1:     {red(bold('VULNERABLE - Server accepts obsolete protocols!'))}")
    else:
        print(f"  Legacy TLS 1.0/1.1:     {green('HARDENED - Server rejects obsolete protocols')}")

    print("\n" + "=" * 74 + "\n")


@register_tool
class CertSentryTool(BaseTool):
    name = "certsentry"
    description = "SSL/TLS certificate expiration monitor, cryptographic cipher auditor & PKI inspector"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "Crypto"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("host", help="Target domain or hostname (e.g. google.com, github.com)")
        parser.add_argument("-p", "--port", type=int, default=443, help="TLS port (default: 443)")
        parser.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3.0)")
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        try:
            report = inspect_certificate(args.host, port=args.port, timeout=args.timeout)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print_cli_report(report)
            return 0
        except Exception as e:
            print(f"[!] CertSentry failed for {args.host}:{args.port} -> {e}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=CertSentryTool.description)
    tool = CertSentryTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))
