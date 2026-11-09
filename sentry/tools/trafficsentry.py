#!/usr/bin/env python3
"""TrafficSentry - Active Network Sockets & Exposed Port Auditor.

Audits active connections and listening ports on the host system to detect
unauthorized listening daemons, backdoors, or services exposed to 0.0.0.0.
Zero external dependencies (Python 3 standard library only).
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool

SENSITIVE_SERVICES = {
    21: "FTP (Plaintext)",
    22: "SSH",
    23: "Telnet (Insecure)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis (No Auth Risk)",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def audit_active_sockets(listening_only: bool = False) -> List[Dict[str, Any]]:
    """Inspect active system sockets using native OS netstat/ss commands."""
    system = platform.system().lower()
    sockets = []

    try:
        if system == "windows":
            # Windows netstat -ano
            cmd = ["netstat", "-ano"]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            # Lines like: TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
            # Or:         TCP    127.0.0.1:8080 0.0.0.0:0    LISTENING    4560
            # Or:         UDP    0.0.0.0:5353   *:*                       2312
            pattern = re.compile(
                r"^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+)(?::(\S+))?\s+([A-Z_]+|\*:\*|\s*)\s+(\d+)",
                re.MULTILINE
            )
            for m in pattern.finditer(output):
                proto, l_addr, l_port, f_addr, f_port, state, pid = m.groups()
                l_port_int = int(l_port)
                f_port = f_port or "-"
                state = state.strip() or ("LISTENING" if proto == "TCP" and f_addr == "0.0.0.0" else "ACTIVE")

                if listening_only and "LISTEN" not in state:
                    continue

                risk_level, risk_desc = _evaluate_socket_risk(proto, l_addr, l_port_int, state)

                sockets.append({
                    "protocol": proto,
                    "local_address": l_addr,
                    "local_port": l_port_int,
                    "foreign_address": f_addr,
                    "foreign_port": f_port,
                    "state": state,
                    "pid": int(pid),
                    "service": SENSITIVE_SERVICES.get(l_port_int, "Custom"),
                    "risk_level": risk_level,
                    "risk_description": risk_desc,
                })
        else:
            # Linux / macOS: try ss or netstat
            cmd = ["ss", "-tulnp"] if system == "linux" else ["netstat", "-an"]
            try:
                output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            except Exception:
                output = subprocess.check_output(["netstat", "-an"], text=True, stderr=subprocess.DEVNULL)

            # Basic parsing for unix lines
            for line in output.splitlines():
                line = line.strip()
                if line.startswith(("tcp", "udp", "TCP", "UDP")):
                    parts = line.split()
                    if len(parts) >= 4:
                        proto = parts[0].upper()
                        # Extract local address and port
                        local_part = parts[4] if len(parts) > 5 else parts[3]
                        if ":" in local_part:
                            l_addr, l_port = local_part.rsplit(":", 1)
                            if l_port.isdigit():
                                l_port_int = int(l_port)
                                state = parts[1] if "LISTEN" in parts[1] else "ACTIVE"
                                risk_level, risk_desc = _evaluate_socket_risk(proto, l_addr, l_port_int, state)
                                sockets.append({
                                    "protocol": proto,
                                    "local_address": l_addr,
                                    "local_port": l_port_int,
                                    "foreign_address": "*",
                                    "foreign_port": "-",
                                    "state": state,
                                    "pid": 0,
                                    "service": SENSITIVE_SERVICES.get(l_port_int, "Custom"),
                                    "risk_level": risk_level,
                                    "risk_description": risk_desc,
                                })

    except Exception:
        pass

    # Sort: HIGH risk first, then by port
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
    sockets.sort(key=lambda s: (risk_order.get(s["risk_level"], 5), s["local_port"]))
    return sockets


def _evaluate_socket_risk(proto: str, addr: str, port: int, state: str) -> tuple:
    """Evaluate if socket exposure represents a security vulnerability."""
    is_listening = "LISTEN" in state.upper() or proto == "UDP"
    is_public = addr in ("0.0.0.0", "::", "*")

    if is_listening and is_public:
        if port in (21, 23, 6379, 27017):
            return "CRITICAL", f"¡Peligro! {SENSITIVE_SERVICES.get(port)} expuesto públicamente a 0.0.0.0 sin cifrado"
        elif port in (3306, 5432, 1433):
            return "HIGH", f"Base de datos {SENSITIVE_SERVICES.get(port)} expuesta en todas las interfaces de red"
        elif port in (22, 3389):
            return "MEDIUM", f"Servicio de administración {SENSITIVE_SERVICES.get(port)} expuesto en 0.0.0.0"
        elif port in SENSITIVE_SERVICES:
            return "LOW", f"Servicio {SENSITIVE_SERVICES.get(port)} escuchando en 0.0.0.0"

    if addr in ("127.0.0.1", "::1", "localhost"):
        return "CLEAN", "Seguro — Sockets enlazados exclusivamente a Localhost"

    return "LOW", "Conexión activa estándar"


def print_cli_report(sockets: List[Dict[str, Any]], listening_only: bool) -> None:
    print("=" * 78)
    print(f" {bold('[TrafficSentry] Host Active Sockets & Port Exposure Auditor')}")
    print(f" Total Sockets Analizados: {len(sockets)} | Modo: {'Solo Escuchando (Listen)' if listening_only else 'Todas las conexiones'}")
    print("=" * 78)

    if not sockets:
        print("\n  No se detectaron sockets activos o permisos insuficientes.\n")
        return

    print(f"\n  {'PROTO':<6} {'LOCAL ENDPOINT':<24} {'ESTADO':<12} {'PID':<8} {'EVALUACIÓN DE RIESGO'}")
    print("  " + "-" * 74)
    for s in sockets:
        ep = f"{s['local_address']}:{s['local_port']}"
        risk = s["risk_level"]
        risk_color = red if risk in ("CRITICAL", "HIGH") else (yellow if risk in ("MEDIUM", "LOW") else green)
        print(f"  {s['protocol']:<6} {ep:<24} {s['state']:<12} {s['pid']:<8} {risk_color(bold(risk))}: {s['risk_description']}")

    print("\n" + "=" * 78 + "\n")


@register_tool
class TrafficSentryTool(BaseTool):
    name = "trafficsentry"
    description = "Active network sockets, process listening ports & 0.0.0.0 exposure auditor"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "Host & Network"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-l", "--listening-only",
            action="store_true",
            help="Show only sockets in LISTENING state (default: False)",
        )
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        sockets = audit_active_sockets(listening_only=args.listening_only)
        if args.json:
            result = {
                "tool": "TrafficSentry",
                "total_sockets": len(sockets),
                "sockets": sockets,
            }
            print(json.dumps(result, indent=2))
        else:
            print_cli_report(sockets, listening_only=args.listening_only)
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=TrafficSentryTool.description)
    tool = TrafficSentryTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))
