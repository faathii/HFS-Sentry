#!/usr/bin/env python3
"""SubnetSweep - Local Network Asset Discovery & IEEE OUI MAC Resolver.

Zero external dependencies (Python 3 standard library only).
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, yellow
from sentry.core.registry import register_tool

# Curated high-frequency IEEE OUI Vendor Database (Prefix to Manufacturer)
OUI_DATABASE = {
    # IoT & Embedded Systems
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",
    "24:0A:C4": "Espressif Inc (ESP32/ESP8266)",
    "30:AE:A4": "Espressif Inc (ESP32/ESP8266)",
    "A4:CF:12": "Espressif Inc (ESP32/ESP8266)",
    "AC:D0:74": "Espressif Inc (ESP32/ESP8266)",
    # Networking & Infrastructure
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:18:0A": "Cisco Systems",
    "00:1A:A0": "Dell Computer Corp",
    "18:66:DA": "Dell Computer Corp",
    "B4:96:91": "Intel Corporate",
    "00:15:5D": "Microsoft Corp (Hyper-V)",
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "08:00:27": "Oracle VirtualBox",
    # Consumer & Routing Hardware
    "00:14:D1": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "C0:25:E9": "TP-Link Technologies",
    "00:1F:33": "Netgear Inc.",
    "20:E5:2A": "Netgear Inc.",
    "00:11:32": "Synology Inc.",
    "00:17:88": "Philips Lighting (Hue Bridge)",
    "F0:9F:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    # Mobile & Workstations
    "3C:22:FB": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "DC:A9:04": "Apple Inc.",
    "F8:FF:C2": "Apple Inc.",
    "40:4E:36": "Samsung Electronics",
    "50:77:05": "Samsung Electronics",
}

DISCOVERY_PROBE_PORTS = [80, 443, 22, 445, 139, 8080, 53]


def get_local_arp_table() -> Dict[str, str]:
    """Parse system ARP cache (cross-platform: Windows, Linux, macOS)."""
    arp_cache: Dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        # Windows pattern: 192.168.1.1       00-11-22-33-44-55     dynamic
        # Linux pattern:   ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+(?:at\s+)?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
        )
        for match in pattern.finditer(output):
            ip, mac = match.groups()
            normalized_mac = mac.replace("-", ":").upper()
            arp_cache[ip] = normalized_mac
    except Exception:
        pass
    return arp_cache


def resolve_oui(mac_address: str) -> str:
    """Lookup vendor from MAC address using IEEE OUI database."""
    if not mac_address:
        return "Unknown"
    normalized = mac_address.replace("-", ":").upper()
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_DATABASE.get(prefix, "Generic / Unregistered Vendor")


def ping_host(ip: str, timeout_sec: float = 0.5) -> bool:
    """ICMP ping probe cross-platform."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    # Windows timeout is in milliseconds, Unix is in seconds
    timeout_val = str(int(timeout_sec * 1000)) if platform.system().lower() == "windows" else str(int(max(1, timeout_sec)))

    cmd = ["ping", param, "1", timeout_param, timeout_val, ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_sec + 0.8)
        return res.returncode == 0
    except Exception:
        return False


def probe_tcp_service(ip: str, port: int, timeout: float = 0.3) -> bool:
    """TCP SYN connect probe to detect active hosts without relying on ICMP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            s.close()
            return True
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return False


def scan_single_host(ip: str, use_icmp: bool = True) -> Optional[Dict[str, Any]]:
    """Probe single IP using hybrid ICMP + TCP SYN."""
    is_alive = False
    open_port = None

    # First attempt: rapid TCP probe on common ports
    for p in DISCOVERY_PROBE_PORTS:
        if probe_tcp_service(ip, p, timeout=0.25):
            is_alive = True
            open_port = p
            break

    # Second attempt: ICMP Ping if TCP probes were silent
    if not is_alive and use_icmp:
        is_alive = ping_host(ip, timeout_sec=0.4)

    if not is_alive:
        return None

    # Hostname reverse lookup
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return {
        "ip": ip,
        "is_alive": True,
        "hostname": hostname or "-",
        "responsive_port": open_port,
    }


def sweep_subnet(cidr: str, workers: int = 40, use_icmp: bool = True) -> List[Dict[str, Any]]:
    """Perform concurrent asset discovery across a CIDR subnet."""
    network = ipaddress.ip_network(cidr, strict=False)
    ip_list = [str(ip) for ip in network.hosts()]

    active_hosts: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {
            executor.submit(scan_single_host, ip, use_icmp): ip
            for ip in ip_list
        }
        for future in as_completed(future_to_ip):
            res = future.result()
            if res:
                active_hosts.append(res)

    # Correlate with system ARP table
    arp_cache = get_local_arp_table()
    for host in active_hosts:
        mac = arp_cache.get(host["ip"], "")
        host["mac"] = mac or "-"
        host["vendor"] = resolve_oui(mac) if mac else "Pending ARP / Remote"

    active_hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return active_hosts


def sweep_subnet_timeline(
    cidr: str,
    duration: float = 30.0,
    interval: float = 5.0,
    workers: int = 40,
    use_icmp: bool = True,
    progress_callback: Optional[Callable[[List[Dict[str, Any]], float], None]] = None,
    stop_check: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """Perform continuous or time-window network discovery over time (e.g. 30 seconds).

    Detects transient devices connecting or disconnecting within the observation period.
    """
    cumulative: Dict[str, Dict[str, Any]] = {}
    start_time = time.time()
    end_time = start_time + duration if duration > 0 else start_time

    while True:
        now = time.time()
        remaining = max(0.0, end_time - now) if duration > 0 else 0.0

        current_hosts = sweep_subnet(cidr=cidr, workers=workers, use_icmp=use_icmp)
        current_ips = {h["ip"] for h in current_hosts}
        now_iso = datetime.datetime.now().strftime("%H:%M:%S")

        for h in current_hosts:
            ip = h["ip"]
            if ip not in cumulative:
                cumulative[ip] = {
                    **h,
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "duration_sec": 0.0,
                    "status": "ACTIVO",
                    "is_new": len(cumulative) > 0,
                    "_start_ts": now,
                    "_last_ts": now,
                }
            else:
                entry = cumulative[ip]
                entry["last_seen"] = now_iso
                entry["status"] = "ACTIVO"
                entry["_last_ts"] = now
                entry["duration_sec"] = round(now - entry["_start_ts"], 1)
                # Update MAC / vendor if resolved later
                if entry.get("mac") in ("-", "", None) and h.get("mac"):
                    entry["mac"] = h["mac"]
                    entry["vendor"] = h.get("vendor", entry.get("vendor"))

        for ip, entry in cumulative.items():
            if ip not in current_ips and entry["status"] == "ACTIVO":
                entry["status"] = "INACTIVO"
                entry["duration_sec"] = round(entry["_last_ts"] - entry["_start_ts"], 1)

        result_list = sorted(cumulative.values(), key=lambda x: ipaddress.ip_address(x["ip"]))

        if progress_callback:
            progress_callback(result_list, remaining)

        if duration <= 0:
            break

        if stop_check and stop_check():
            break

        if now >= end_time:
            break

        time.sleep(min(interval, max(0.5, end_time - now)))

    return result_list


def print_cli_report(hosts: List[Dict[str, Any]], cidr: str, duration: float) -> None:
    """Print formatted SubnetSweep report."""
    print("=" * 76)
    print(f" {bold('[SubnetSweep] Local Network Asset Discovery & IEEE OUI Resolver')}")
    print(f" Target Subnet: {cyan(cidr)} | Active Hosts Found: {len(hosts)} (Scan: {duration}s)")
    print("=" * 76)

    if not hosts:
        print(f"\n  No responsive hosts detected in subnet {cidr}.\n")
        return

    print(f"\n  {'IP ADDRESS':<16} {'MAC ADDRESS':<18} {'VENDOR / HARDWARE':<26} {'HOSTNAME'}")
    print("  " + "-" * 72)
    for h in hosts:
        ip_str = green(bold(h["ip"]))
        mac_str = h["mac"]
        vendor_str = cyan(h["vendor"]) if h["vendor"] != "-" else "-"
        print(f"  {ip_str:<25} {mac_str:<18} {vendor_str:<35} {h['hostname']}")

    print("\n" + "=" * 76 + "\n")


@register_tool
class SubnetSweepTool(BaseTool):
    name = "subnetsweep"
    description = "Concurrent local network asset discovery, ARP mapping & IEEE OUI hardware fingerprinting"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "Infrastructure"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("cidr", help="Target CIDR subnet (e.g. 192.168.1.0/24, 10.0.0.0/24)")
        parser.add_argument("-t", "--threads", type=int, default=40, help="Worker threads (default: 40)")
        parser.add_argument("--no-icmp", action="store_true", help="Disable ICMP ping (use TCP probes only)")
        parser.add_argument(
            "-d", "--duration",
            type=float,
            default=0.0,
            help="Observation window in seconds (e.g. 30.0 for 30s monitoring; default: 0 = instant snapshot)",
        )
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        start_t = time.time()
        try:
            if args.duration > 0:
                print(f"[*] Iniciando ventana de barrido de red de {args.duration}s en {args.cidr}...")
                hosts = sweep_subnet_timeline(
                    cidr=args.cidr,
                    duration=args.duration,
                    workers=args.threads,
                    use_icmp=not args.no_icmp,
                )
            else:
                hosts = sweep_subnet(args.cidr, workers=args.threads, use_icmp=not args.no_icmp)
            duration = round(time.time() - start_t, 2)

            if args.json:
                result = {
                    "tool": "SubnetSweep",
                    "subnet": args.cidr,
                    "duration_seconds": duration,
                    "active_hosts_count": len(hosts),
                    "hosts": hosts,
                }
                print(json.dumps(result, indent=2))
            else:
                print_cli_report(hosts, args.cidr, duration)
            return 0
        except Exception as e:
            print(f"[!] SubnetSweep error: {e}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=SubnetSweepTool.description)
    tool = SubnetSweepTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))

