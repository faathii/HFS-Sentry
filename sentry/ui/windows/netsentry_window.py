"""Independent Desktop Window for NetSentry."""

import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from sentry.tools.netsentry import (
    DEFAULT_PORTS,
    PLAINTEXT_RISK_PORTS,
    SERVICE_NAMES,
    audit_http_headers,
    resolve_host,
    scan_single_port,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class NetSentryWindow(BaseToolWindow):
    """NetSentry Independent GUI Application."""

    tool_id = "netsentry"
    tool_title = "NetSentry — Port Scanner & OWASP Auditor"
    tool_category = "Network & Web"
    tool_version = "1.0.0"
    icon_filename = "netsentry.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct target input, port list, thread controls and action buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        # Target entry
        ttk.Label(row1, text="Host / IP Objetivo:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_target = ttk.Entry(row1, width=28)
        self.entry_target.insert(0, "scanme.nmap.org")
        self.entry_target.pack(side="left", padx=(0, 16))

        # Ports entry
        ttk.Label(row1, text="Puertos (ej. 22,80,443 o 20-100):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_ports = ttk.Entry(row1, width=32)
        self.entry_ports.insert(0, ",".join(str(p) for p in DEFAULT_PORTS))
        self.entry_ports.pack(side="left", padx=(0, 16))

        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(8, 2))

        # Threads
        ttk.Label(row2, text="Hilos Concurrencia:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_threads = ttk.Spinbox(row2, from_=1, to=50, width=5)
        self.spin_threads.set("20")
        self.spin_threads.pack(side="left", padx=(0, 16))

        # Web audit checkbox
        self.var_web_audit = tk.BooleanVar(value=True)
        self.chk_web = ttk.Checkbutton(row2, text="Auditar Cabeceras OWASP (80/443)", variable=self.var_web_audit)
        self.chk_web.pack(side="left", padx=(0, 20))

        # Action Buttons
        self.btn_run = ttk.Button(row2, text="▶ Iniciar Escaneo", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

        self.btn_stop = ttk.Button(row2, text="⏹ Detener", style="Danger.TButton", command=self.stop_analysis)
        self.btn_stop.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create structured Treeview table for discovered open ports."""
        columns = ("port", "state", "service", "banner", "risk")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("port", text="PUERTO")
        self.tree.heading("state", text="ESTADO")
        self.tree.heading("service", text="SERVICIO")
        self.tree.heading("banner", text="BANNER DE SOFTWARE")
        self.tree.heading("risk", text="ALERTA DE SEGURIDAD")

        self.tree.column("port", width=80, anchor="center")
        self.tree.column("state", width=90, anchor="center")
        self.tree.column("service", width=120, anchor="w")
        self.tree.column("banner", width=260, anchor="w")
        self.tree.column("risk", width=280, anchor="w")

        # Color tags
        self.tree.tag_configure("risk_high", foreground=COLORS["accent_red"])
        self.tree.tag_configure("clean", foreground=COLORS["accent_green"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def start_analysis(self) -> None:
        """Parse inputs and trigger asynchronous scan."""
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Dato Requerido", "Por favor ingrese un host o IP objetivo.")
            return

        ports_raw = self.entry_ports.get().strip()
        port_list = []
        try:
            for part in ports_raw.split(","):
                part = part.strip()
                if "-" in part:
                    s, e = map(int, part.split("-"))
                    port_list.extend(range(s, e + 1))
                else:
                    port_list.append(int(part))
        except Exception:
            messagebox.showerror("Formato Inválido", "Formato de puertos no válido. Use por ejemplo: 22,80,443 o 20-100")
            return

        workers = int(self.spin_threads.get())
        audit_web = self.var_web_audit.get()

        self.clear_results()
        self.log(f"Iniciando escaneo real sobre '{target}' ({len(port_list)} puertos con {workers} hilos)...")

        def _worker():
            start_t = time.time()
            try:
                ip = resolve_host(target)
                self.log(f"Host resuelto correctamente: {target} -> {ip}")
            except Exception as e:
                self.log(f"[ERROR] No se pudo resolver host '{target}': {e}")
                return

            open_ports = []
            for idx, port in enumerate(port_list, 1):
                if self.stop_requested.is_set():
                    self.log("[!] Escaneo interrumpido por el usuario.")
                    break

                res = scan_single_port(ip, port, timeout=0.5)
                if res:
                    open_ports.append(res)
                    tag = "risk_high" if res["plaintext_risk"] else "clean"
                    alert_txt = f"! {res['risk_description']}" if res["plaintext_risk"] else "Estándar / Seguro"
                    self.after(0, lambda r=res, t=tag, a=alert_txt: self.tree.insert(
                        "", "end", values=(r["port"], r["state"], r["service"], r["banner"] or "-", a), tags=(t,)
                    ))
                    self.log(f"[ABIERTO] Puerto {res['port']} ({res['service']}) - {res['banner']}")

            elapsed = round(time.time() - start_t, 2)
            self.log(f"Escaneo de puertos completado en {elapsed}s. Puertos abiertos detectados: {len(open_ports)}")

            # OWASP Web Audit
            web_results = None
            if audit_web and not self.stop_requested.is_set():
                open_nums = [p["port"] for p in open_ports]
                web_port = 443 if (443 in open_nums or 8443 in open_nums) else (80 if 80 in open_nums else None)
                if web_port or 443 in port_list or 80 in port_list:
                    p = web_port or (443 if 443 in port_list else 80)
                    self.log(f"Ejecutando auditoría de cabeceras OWASP sobre puerto {p}...")
                    web_results = audit_http_headers(target, port=p)
                    self.log(f"Auditoría web finalizada. Calificación: [{web_results['grade']}] ({web_results['score_fraction']})")

            self.latest_results = {
                "tool": "NetSentry",
                "target": target,
                "ip": ip,
                "elapsed_seconds": elapsed,
                "open_ports": open_ports,
                "web_audit": web_results,
            }

            self._update_summary(self.latest_results)

        self.execute_async(_worker)

    def _update_summary(self, data: dict) -> None:
        """Render executive report in summary tab."""
        def _render():
            self.summary_text.delete("1.0", "end")
            text = [
                "=========================================================================",
                f" INFORME DE DIAGNÓSTICO PERIMETRAL — NETSENTRY",
                "=========================================================================",
                f" Objetivo Auditado:       {data['target']} ({data['ip']})",
                f" Duración del Escaneo:    {data['elapsed_seconds']} segundos",
                f" Puertos Abiertos:        {len(data['open_ports'])}",
                "",
                "--- PUERTOS DETECTADOS ---",
            ]
            if not data["open_ports"]:
                text.append("  [✔] Ningún puerto abierto detectado en la lista sondeada.")
            else:
                for p in data["open_ports"]:
                    risk = f"(!) RIESGO: {p['risk_description']}" if p["plaintext_risk"] else "OK"
                    text.append(f"  • Puerto {p['port']}/TCP ({p['service']}) -> {risk}")

            if data.get("web_audit"):
                w = data["web_audit"]
                text.extend([
                    "",
                    "--- AUDITORÍA DE SEGURIDAD WEB (OWASP) ---",
                    f" Endpoint Auditado:       {w['url']} (Código HTTP: {w['status_code']})",
                    f" Calificación Obtenida:   GRADO [{w['grade']}] ({w['score_fraction']} cabeceras presentes)",
                    "",
                ])
                for name, d in w.get("headers_audited", {}).items():
                    status = "[PASÓ]" if d["present"] else "[FALLÓ]"
                    text.append(f"  {status:<8} {name:<28} - {d['purpose']}")

            text.append("\n=========================================================================\n")
            self.summary_text.insert("end", "\n".join(text))

        self.after(0, _render)

    def clear_results(self) -> None:
        """Clear treeview and console."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.console_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")
        self.latest_results = None
        self.set_status("Listo.")

