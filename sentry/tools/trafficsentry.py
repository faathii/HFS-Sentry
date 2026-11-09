#!/usr/bin/env python3
"""TrafficSentry - Active Network Sockets & Exposed Port Auditor.

Audits active connections and listening ports on the host system to detect
unauthorized listening daemons, backdoors, or services exposed to 0.0.0.0.
Zero external dependencies (Python 3 standard library only).
"""

import argparse
import datetime
import json
import os
import platform
import re
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

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


_PROC_CACHE: Dict[int, str] = {
    0: "[System Idle]",
    4: "System",
}


def get_process_name_by_pid(pid: int) -> str:
    """Resolve process executable name from PID without external dependencies."""
    if pid in _PROC_CACHE:
        return _PROC_CACHE[pid]
    if pid <= 0:
        return "Unknown"

    system = platform.system().lower()
    if system == "windows":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h:
                buf = ctypes.create_unicode_buffer(1024)
                size = ctypes.c_ulong(1024)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    name = os.path.basename(buf.value)
                    ctypes.windll.kernel32.CloseHandle(h)
                    if name:
                        _PROC_CACHE[pid] = name
                        return name
                ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass
    elif system == "linux":
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
                name = f.read().strip()
                if name:
                    _PROC_CACHE[pid] = name
                    return name
        except Exception:
            pass

    fallback = f"PID-{pid}"
    return fallback


def audit_active_sockets(listening_only: bool = False) -> List[Dict[str, Any]]:
    """Inspect active system sockets using native OS netstat/ss commands."""
    system = platform.system().lower()
    sockets = []

    try:
        if system == "windows":
            # Windows netstat -ano
            cmd = ["netstat", "-ano"]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line or not line.startswith(("TCP", "UDP")):
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                proto = parts[0].upper()
                local_part = parts[1]
                remote_part = parts[2]
                state = parts[3] if len(parts) >= 5 else "ACTIVE"
                pid_str = parts[4] if len(parts) >= 5 else parts[3]

                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0

                # Split local endpoint
                if ":" in local_part:
                    l_addr, l_port_str = local_part.rsplit(":", 1)
                    l_port_int = int(l_port_str) if l_port_str.isdigit() else 0
                else:
                    l_addr, l_port_int = local_part, 0

                # Split remote endpoint cleanly
                if ":" in remote_part:
                    f_addr, f_port = remote_part.rsplit(":", 1)
                else:
                    f_addr, f_port = remote_part, "-"

                state_clean = state.strip()
                if listening_only and "LISTEN" not in state_clean.upper():
                    continue

                proc_name = get_process_name_by_pid(pid)
                risk_level, risk_desc = _evaluate_socket_risk(proto, l_addr, l_port_int, state_clean)

                sockets.append({
                    "protocol": proto,
                    "process_name": proc_name,
                    "local_address": l_addr,
                    "local_port": l_port_int,
                    "foreign_address": f_addr,
                    "foreign_port": f_port,
                    "state": state_clean,
                    "pid": pid,
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

            for line in output.splitlines():
                line = line.strip()
                if line.startswith(("tcp", "udp", "TCP", "UDP")):
                    parts = line.split()
                    if len(parts) >= 4:
                        proto = parts[0].upper()
                        local_part = parts[4] if len(parts) > 5 else parts[3]
                        if ":" in local_part:
                            l_addr, l_port = local_part.rsplit(":", 1)
                            if l_port.isdigit():
                                l_port_int = int(l_port)
                                state = parts[1] if "LISTEN" in parts[1] else "ACTIVE"
                                risk_level, risk_desc = _evaluate_socket_risk(proto, l_addr, l_port_int, state)
                                sockets.append({
                                    "protocol": proto,
                                    "process_name": "System",
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


def audit_sockets_timeline(
    duration: float = 30.0,
    interval: float = 1.0,
    listening_only: bool = False,
    progress_callback: Optional[Callable[[List[Dict[str, Any]], float], None]] = None,
    stop_check: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """Capture socket activity over a cumulative time window (e.g. 30 seconds).

    Retains ephemeral connections that open and close during the observation window,
    recording their appearance time, duration, and whether they remain active.
    """
    cumulative: Dict[tuple, Dict[str, Any]] = {}
    start_time = time.time()
    end_time = start_time + duration if duration > 0 else start_time

    while True:
        now = time.time()
        elapsed = now - start_time
        remaining = max(0.0, end_time - now) if duration > 0 else 0.0

        current_sockets = audit_active_sockets(listening_only=listening_only)
        current_keys = set()

        for s in current_sockets:
            key = (s["protocol"], s["local_address"], s["local_port"], s["foreign_address"], s["foreign_port"], s["pid"])
            current_keys.add(key)
            now_iso = datetime.datetime.now().strftime("%H:%M:%S")

            if key not in cumulative:
                cumulative[key] = {
                    **s,
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "duration_sec": 0.0,
                    "timeline_status": "ACTIVO",
                    "seen_count": 1,
                    "_start_ts": now,
                    "_last_ts": now,
                }
            else:
                entry = cumulative[key]
                entry["last_seen"] = now_iso
                entry["seen_count"] += 1
                entry["timeline_status"] = "ACTIVO"
                entry["_last_ts"] = now
                entry["duration_sec"] = round(now - entry["_start_ts"], 1)

        # Mark sockets that disappeared as CLOSED
        for key, entry in cumulative.items():
            if key not in current_keys and entry["timeline_status"] == "ACTIVO":
                entry["timeline_status"] = "CERRADO"
                entry["duration_sec"] = round(entry["_last_ts"] - entry["_start_ts"], 1)

        # Prepare sorted list
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
        result_list = sorted(
            cumulative.values(),
            key=lambda x: (
                0 if x["timeline_status"] == "ACTIVO" else 1,
                risk_order.get(x["risk_level"], 5),
                x["local_port"],
            ),
        )

        if progress_callback:
            progress_callback(result_list, remaining)

        if duration <= 0:
            break

        if stop_check and stop_check():
            break

        if now >= end_time:
            break

        time.sleep(min(interval, max(0.1, end_time - now)))

    return result_list


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
        parser.add_argument(
            "-d", "--duration",
            type=float,
            default=0.0,
            help="Observation window in seconds (e.g. 30.0 for 30s monitoring; default 0 = instant snapshot)",
        )
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        if args.duration > 0:
            print(f"[*] Iniciando ventana de observación de {args.duration}s (muestreo acumulativo cada 1s)...")
            sockets = audit_sockets_timeline(duration=args.duration, listening_only=args.listening_only)
        else:
            sockets = audit_active_sockets(listening_only=args.listening_only)

        if args.json:
            result = {
                "tool": "TrafficSentry",
                "duration_seconds": args.duration,
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

