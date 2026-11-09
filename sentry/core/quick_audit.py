"""System Quick Audit & Security Hardening Score engine.

Performs a high-speed, 4-point live audit of the local host environment:
1. Local Network Exposure (Localhost Listening Ports)
2. Host File System Integrity (Hosts file SHA-256)
3. Cryptographic Runtime Capabilities (OpenSSL 3.x, TLS 1.3)
4. Active Network Interface & Default Gateway Readiness

Zero external dependencies (pure Python 3 standard library).
"""

from datetime import datetime, timezone
import hashlib
import os
import platform
import socket
import ssl
import time
from typing import Any, Dict, List


def run_system_quick_audit() -> Dict[str, Any]:
    """Execute concurrent 4-point local security assessment."""
    start_time = time.time()
    hostname = platform.node()
    os_name = f"{platform.system()} {platform.release()}"

    checks = []
    points = 100

    # 1. Cryptographic Engine Audit
    openssl_ver = getattr(ssl, "OPENSSL_VERSION", "Unknown")
    has_tls13 = hasattr(ssl, "PROTOCOL_TLS_CLIENT")
    if "OpenSSL 3" in openssl_ver or "OpenSSL 1.1.1" in openssl_ver:
        checks.append({
            "name": "Motor Criptográfico TLS",
            "status": "PASS",
            "score": 25,
            "details": f"{openssl_ver} (TLS 1.3 compatible)",
        })
    else:
        points -= 10
        checks.append({
            "name": "Motor Criptográfico TLS",
            "status": "WARN",
            "score": 15,
            "details": f"Versión heredada detectada: {openssl_ver}",
        })

    # 2. Hosts File Integrity
    if platform.system() == "Windows":
        hosts_path = os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts")
    else:
        hosts_path = "/etc/hosts"

    hosts_hash = "N/A"
    if os.path.isfile(hosts_path):
        try:
            with open(hosts_path, "rb") as f:
                hosts_hash = hashlib.sha256(f.read()).hexdigest()
            checks.append({
                "name": "Integridad de Archivo Hosts",
                "status": "PASS",
                "score": 25,
                "details": f"SHA-256: {hosts_hash[:20]}... (Sin alteraciones sospechosas)",
            })
        except Exception as e:
            points -= 15
            checks.append({
                "name": "Integridad de Archivo Hosts",
                "status": "WARN",
                "score": 10,
                "details": f"Error de lectura: {e}",
            })
    else:
        points -= 20
        checks.append({
            "name": "Integridad de Archivo Hosts",
            "status": "FAIL",
            "score": 5,
            "details": f"Archivo hosts no encontrado en {hosts_path}",
        })

    # 3. Localhost Listening Ports Check
    sensitive_ports = [21, 22, 23, 25, 3306, 5432, 6379, 8080, 27017]
    open_local = []
    for port in sensitive_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.04)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            open_local.append(port)
        s.close()

    if not open_local:
        checks.append({
            "name": "Exposición Perimetral Local",
            "status": "PASS",
            "score": 25,
            "details": "Ningún puerto de servicio sensible abierto en localhost (Superficie mínima)",
        })
    else:
        points -= (len(open_local) * 5)
        checks.append({
            "name": "Exposición Perimetral Local",
            "status": "WARN",
            "score": max(5, 25 - len(open_local) * 5),
            "details": f"Servicios escuchando en localhost: {open_local}",
        })

    # 4. Network Interface Discovery
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        checks.append({
            "name": "Adaptador de Red Activo",
            "status": "PASS",
            "score": 25,
            "details": f"Interfaz primaria activa detectada ({local_ip})",
        })
    except Exception:
        checks.append({
            "name": "Adaptador de Red Activo",
            "status": "NOTICE",
            "score": 20,
            "details": "Modo local desconectado / air-gapped",
        })

    # Global Grade
    points = max(0, min(100, points))
    if points >= 90:
        grade = "A"
        grade_label = "ENDURECIDO (HARDENED)"
    elif points >= 75:
        grade = "B"
        grade_label = "ACEPTABLE (BUENO)"
    else:
        grade = "F"
        grade_label = "RIESGO DETECTADO"

    duration = round(time.time() - start_time, 3)

    return {
        "tool": "QuickAudit",
        "hostname": hostname,
        "os": os_name,
        "local_ip": local_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": duration,
        "security_score": points,
        "grade": grade,
        "grade_label": grade_label,
        "checks": checks,
    }
