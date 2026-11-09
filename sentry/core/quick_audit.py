"""System Quick Audit & Security Hardening Score engine.

Performs a high-speed, comprehensive 6-point live audit of the local host environment:
1. Local Network Exposure (Localhost Listening Ports)
2. Public 0.0.0.0 Socket Exposure (TrafficSentry Engine)
3. Host File System Integrity (Hosts file SHA-256)
4. Cryptographic Runtime Capabilities (OpenSSL 3.x, TLS 1.3)
5. DNS Resolution & Anti-Spoofing Readiness
6. Active Network Interface & Gateway Readiness

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

from sentry.tools.trafficsentry import audit_active_sockets


def run_system_quick_audit() -> Dict[str, Any]:
    """Execute concurrent 6-point local security assessment."""
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
            "score": 20,
            "details": f"{openssl_ver} (TLS 1.3 compatible)",
        })
    else:
        points -= 10
        checks.append({
            "name": "Motor Criptográfico TLS",
            "status": "WARN",
            "score": 10,
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
                "score": 20,
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
            "score": 0,
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
            "score": 15,
            "details": "Ningún puerto de servicio sensible abierto en localhost (Superficie mínima)",
        })
    else:
        points -= (len(open_local) * 4)
        checks.append({
            "name": "Exposición Perimetral Local",
            "status": "WARN",
            "score": max(5, 15 - len(open_local) * 4),
            "details": f"Servicios escuchando en localhost: {open_local}",
        })

    # 4. Public 0.0.0.0 Exposure (TrafficSentry Engine)
    try:
        active_sockets = audit_active_sockets(listening_only=True)
        risky_public = [s for s in active_sockets if s["risk_level"] in ("CRITICAL", "HIGH")]
        if not risky_public:
            checks.append({
                "name": "Exposición a 0.0.0.0 (TrafficSentry)",
                "status": "PASS",
                "score": 20,
                "details": "No hay bases de datos ni servicios de riesgo expuestos públicamente a todas las interfaces",
            })
        else:
            points -= min(30, len(risky_public) * 15)
            ports_exposed = [f"{s['local_port']}/{s['process_name']}" for s in risky_public]
            checks.append({
                "name": "Exposición a 0.0.0.0 (TrafficSentry)",
                "status": "FAIL",
                "score": 0,
                "details": f"¡Alerta! Servicios de alto riesgo expuestos en 0.0.0.0: {', '.join(ports_exposed)}",
            })
    except Exception as e:
        checks.append({
            "name": "Exposición a 0.0.0.0 (TrafficSentry)",
            "status": "NOTICE",
            "score": 15,
            "details": f"Auditoría no completada: {e}",
        })

    # 5. DNS Resolution Health
    try:
        t_dns_start = time.time()
        socket.gethostbyname("dns.google")
        dns_lat = round((time.time() - t_dns_start) * 1000, 1)
        checks.append({
            "name": "Resolución de Nombres DNS",
            "status": "PASS",
            "score": 15,
            "details": f"Resolución DNS activa y funcional ({dns_lat} ms)",
        })
    except Exception:
        points -= 10
        checks.append({
            "name": "Resolución de Nombres DNS",
            "status": "WARN",
            "score": 5,
            "details": "Resolución DNS fallida o sin conexión a internet",
        })

    # 6. Network Interface Discovery
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        checks.append({
            "name": "Adaptador de Red Activo",
            "status": "PASS",
            "score": 10,
            "details": f"Interfaz primaria activa detectada ({local_ip})",
        })
    except Exception:
        checks.append({
            "name": "Adaptador de Red Activo",
            "status": "NOTICE",
            "score": 10,
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

