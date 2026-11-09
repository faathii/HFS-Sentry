#!/usr/bin/env python3
"""DnsProbe - DNS Records & Email Security (SPF, DMARC, DNSSEC) Auditor.

Zero external dependencies (Python 3 standard library only).
Queries DNS via DoH (DNS-over-HTTPS) JSON API and native socket resolution.
"""

import argparse
import json
import socket
import sys
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool

# Primary and fallback DNS-over-HTTPS JSON API endpoints
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    257: "CAA",
}


def query_doh(domain: str, record_type: str = "A", timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Query DNS-over-HTTPS endpoint using standard library urllib."""
    headers = {
        "Accept": "application/dns-json",
        "User-Agent": "HFS-Sentry/1.0 (DnsProbe Auditor)",
    }

    params = urllib.parse.urlencode({"name": domain, "type": record_type})

    for endpoint in DOH_ENDPOINTS:
        url = f"{endpoint}?{params}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data
        except Exception:
            continue
    return None


def audit_email_security(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Audit SPF, DMARC, and MX records for email spoofing vulnerability."""
    results = {
        "spf": {"found": False, "raw": None, "status": "FAIL", "notes": "No SPF record found"},
        "dmarc": {"found": False, "raw": None, "policy": None, "status": "FAIL", "notes": "No DMARC record found"},
        "mx_records": [],
        "overall_email_rating": "VULNERABLE",
    }

    # 1. Query TXT records on apex domain for SPF
    txt_data = query_doh(domain, record_type="TXT", timeout=timeout)
    if txt_data and "Answer" in txt_data:
        for ans in txt_data["Answer"]:
            data = ans.get("data", "").strip('"').strip("'")
            if "v=spf1" in data:
                results["spf"]["found"] = True
                results["spf"]["raw"] = data
                if "-all" in data:
                    results["spf"]["status"] = "PASS"
                    results["spf"]["notes"] = "Strict hard fail (-all) configured"
                elif "~all" in data:
                    results["spf"]["status"] = "PASS"
                    results["spf"]["notes"] = "Soft fail (~all) configured"
                elif "+all" in data:
                    results["spf"]["status"] = "FAIL"
                    results["spf"]["notes"] = "CRITICAL: +all allows anyone to spoof email!"
                else:
                    results["spf"]["status"] = "WARN"
                    results["spf"]["notes"] = "Neutral or missing all mechanism"
                break

    # 2. Query TXT records on _dmarc.<domain>
    dmarc_data = query_doh(f"_dmarc.{domain}", record_type="TXT", timeout=timeout)
    if dmarc_data and "Answer" in dmarc_data:
        for ans in dmarc_data["Answer"]:
            data = ans.get("data", "").strip('"').strip("'")
            if "v=DMARC1" in data:
                results["dmarc"]["found"] = True
                results["dmarc"]["raw"] = data
                # Extract policy
                parts = [p.strip() for p in data.split(";")]
                policy = "none"
                for p in parts:
                    if p.startswith("p="):
                        policy = p.split("=")[1].strip()
                        break
                results["dmarc"]["policy"] = policy
                if policy == "reject":
                    results["dmarc"]["status"] = "PASS"
                    results["dmarc"]["notes"] = "Highest security: reject spoofed emails"
                elif policy == "quarantine":
                    results["dmarc"]["status"] = "PASS"
                    results["dmarc"]["notes"] = "Quarantine policy configured"
                else:
                    results["dmarc"]["status"] = "WARN"
                    results["dmarc"]["notes"] = "Policy 'p=none' only monitors, does not block spoofing"
                break

    # 3. Query MX records
    mx_data = query_doh(domain, record_type="MX", timeout=timeout)
    if mx_data and "Answer" in mx_data:
        for ans in mx_data["Answer"]:
            results["mx_records"].append(ans.get("data", ""))

    # Overall calculation
    spf_ok = results["spf"]["status"] == "PASS"
    dmarc_ok = results["dmarc"]["status"] == "PASS"
    if spf_ok and dmarc_ok:
        results["overall_email_rating"] = "HARDENED"
    elif spf_ok or dmarc_ok:
        results["overall_email_rating"] = "PARTIALLY PROTECTED"
    else:
        results["overall_email_rating"] = "VULNERABLE (Spoofing Risk)"

    return results


def run_dnsprobe(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Execute complete DNS and email security audit."""
    # Strip protocol or paths if provided by mistake
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()

    records_collected: Dict[str, List[str]] = {}
    dnssec_validated = False

    types_to_probe = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]
    for rtype in types_to_probe:
        doh_resp = query_doh(clean_domain, record_type=rtype, timeout=timeout)
        if doh_resp:
            if doh_resp.get("AD"):  # Authenticated Data flag (DNSSEC)
                dnssec_validated = True
            answers = doh_resp.get("Answer", [])
            if answers:
                records_collected[rtype] = [
                    a.get("data", "").strip('"').strip("'") for a in answers
                ]

    # Native socket resolution fallback for A record
    if "A" not in records_collected:
        try:
            _, _, ips = socket.gethostbyname_ex(clean_domain)
            if ips:
                records_collected["A"] = ips
        except Exception:
            pass

    email_sec = audit_email_security(clean_domain, timeout=timeout)

    return {
        "tool": "DnsProbe",
        "domain": clean_domain,
        "dnssec_validated": dnssec_validated,
        "records": records_collected,
        "email_security": email_sec,
    }


def print_cli_report(data: Dict[str, Any]) -> None:
    """Print structured CLI report for DnsProbe."""
    print("=" * 76)
    print(f" {bold('[DnsProbe] DNS Reconnaissance & Email Security Auditor')}")
    print(f" Target Domain: {cyan(data['domain'])}")
    print("=" * 76)

    dnssec_tag = green("[PASS] Enabled (AD Flag Active)") if data["dnssec_validated"] else yellow("[NOTICE] Not validated via DoH")
    print(f"\n  DNSSEC Status:          {dnssec_tag}")

    print(f"\n--- {bold('Resolved DNS Records')} ---")
    if not data["records"]:
        print("  No public records resolved.")
    else:
        for rtype, values in data["records"].items():
            print(f"  {bold(rtype):<6} ({len(values)}):")
            for v in values:
                print(f"         └── {v}")

    email_sec = data["email_security"]
    rating = email_sec["overall_email_rating"]
    rating_color = green if "HARDENED" in rating else (yellow if "PARTIALLY" in rating else red)

    print(f"\n--- {bold('Email Spoofing Defense (SPF & DMARC)')} ---")
    print(f"  Overall Posture:        {rating_color(bold(rating))}")

    # SPF
    spf = email_sec["spf"]
    spf_tag = green("[PASS]") if spf["status"] == "PASS" else (yellow("[WARN]") if spf["status"] == "WARN" else red("[FAIL]"))
    print(f"  SPF Record:             {spf_tag} {spf['notes']}")
    if spf["raw"]:
        print(f"                          └── {spf['raw']}")

    # DMARC
    dmarc = email_sec["dmarc"]
    dmarc_tag = green("[PASS]") if dmarc["status"] == "PASS" else (yellow("[WARN]") if dmarc["status"] == "WARN" else red("[FAIL]"))
    print(f"  DMARC Record:           {dmarc_tag} {dmarc['notes']}")
    if dmarc["raw"]:
        print(f"                          └── {dmarc['raw']}")

    print("\n" + "=" * 76 + "\n")


@register_tool
class DnsProbeTool(BaseTool):
    name = "dnsprobe"
    description = "DNS record reconnaissance & email spoofing defense auditor (SPF, DMARC, DNSSEC)"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "DNS & Email"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("domain", help="Target domain to inspect (e.g. google.com, github.com)")
        parser.add_argument("--timeout", type=float, default=3.0, help="Query timeout in seconds (default: 3.0)")
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        try:
            report = run_dnsprobe(args.domain, timeout=args.timeout)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print_cli_report(report)
            return 0
        except Exception as e:
            print(f"[!] DnsProbe failed: {e}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DnsProbeTool.description)
    tool = DnsProbeTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))
