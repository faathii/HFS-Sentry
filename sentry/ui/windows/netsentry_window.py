"""Independent Desktop Window for NetSentry with responsive layout and live stopwatch."""

import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional

from sentry.tools.netsentry import (
    DEFAULT_PORTS,
    PLAINTEXT_RISK_PORTS,
    SERVICE_NAMES,
    audit_http_headers,
    resolve_host,
    scan_ports,
    scan_ports_timeline,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class NetSentryWindow(BaseToolWindow):
    """NetSentry Independent GUI Application with Service Watchdog."""

    tool_id = "netsentry"
    tool_title = "NetSentry — Port Scanner & OWASP Auditor"
    tool_category = "Network & Web"
    tool_version = "1.1.0"
    icon_filename = "netsentry.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct target input, duration controls, port list and responsive action buttons."""
        self.is_running = False

        # Row 1: Target parameters
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=(2, 6))

        ttk.Label(row1, text="Host / IP:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_target = ttk.Entry(row1, width=22)
        self.entry_target.insert(0, "scanme.nmap.org")
        self.entry_target.pack(side="left", padx=(0, 12))

        ttk.Label(row1, text="Puertos:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_ports = ttk.Entry(row1, width=32)
        self.entry_ports.insert(0, ",".join(str(p) for p in DEFAULT_PORTS))
        self.entry_ports.pack(side="left", fill="x", expand=True, padx=(0, 12))

        self.var_web_audit = tk.BooleanVar(value=True)
        self.chk_web = ttk.Checkbutton(row1, text="Cabeceras OWASP (80/443)", variable=self.var_web_audit)
        self.chk_web.pack(side="left", padx=(0, 4))

        # Row 2: Action toolbar (Buttons & Banner guaranteed visible)
        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(2, 2))

        ttk.Label(row2, text="Ventana:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.combo_duration = ttk.Combobox(
            row2,
            values=[
                "⚡ Escaneo Instantáneo",
                "⏱️ Ventana 30s (Watchdog de Servicios)",
                "⏱️ Ventana 60s",
                "🔄 Monitoreo Continuo",
            ],
            state="readonly",
            width=26,
        )
        self.combo_duration.current(0)
        self.combo_duration.pack(side="left", padx=(0, 12))

        self.banner_var = tk.StringVar(value="Listo para auditar puertos y seguridad perimetral.")
        self.lbl_banner = ttk.Label(row2, textvariable=self.banner_var, font=FONTS["code_small"], foreground=COLORS["accent_cyan"])
        self.lbl_banner.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_stop = ttk.Button(row2, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=(4, 0))

        self.btn_run = ttk.Button(row2, text="▶ Iniciar Escaneo", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create structured Treeview table for discovered open ports with watchdog stability."""
        columns = ("port", "state", "stability", "lat", "service", "banner", "risk")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("port", text="PUERTO")
        self.tree.heading("state", text="ESTADO")
        self.tree.heading("stability", text="ESTABILIDAD")
        self.tree.heading("lat", text="LATENCIA")
        self.tree.heading("service", text="SERVICIO")
        self.tree.heading("banner", text="BANNER DE SOFTWARE")
        self.tree.heading("risk", text="EVALUACIÓN DE RIESGO")

        self.tree.column("port", width=75, anchor="center")
        self.tree.column("state", width=85, anchor="center")
        self.tree.column("stability", width=110, anchor="center")
        self.tree.column("lat", width=85, anchor="center")
        self.tree.column("service", width=110, anchor="w")
        self.tree.column("banner", width=240, anchor="w")
        self.tree.column("risk", width=250, anchor="w")

        self.tree.tag_configure("risk_high", foreground=COLORS["accent_red"])
        self.tree.tag_configure("clean", foreground=COLORS["accent_green"])
        self.tree.tag_configure("status_intermittent", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("status_down", foreground="#64748b")

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _parse_ports(self, text: str) -> List[int]:
        ports = set()
        for item in text.split(","):
            item = item.strip()
            if not item:
                continue
            if "-" in item:
                start, end = item.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(item))
        return sorted(list(ports))

    def _get_selected_duration(self) -> float:
        val = self.combo_duration.get()
        if "30s" in val:
            return 30.0
        elif "60s" in val:
            return 60.0
        elif "Continuo" in val:
            return 999999.0
        return 0.0

    def start_analysis(self) -> None:
        if self.is_running:
            return

        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Dato Requerido", "Por favor ingrese un host o IP válido.")
            return

        try:
            ports = self._parse_ports(self.entry_ports.get())
        except Exception:
            messagebox.showerror("Error de Formato", "Formato de puertos no válido (ej. 22,80,443 o 20-100).")
            return

        duration = self._get_selected_duration()
        do_web = self.var_web_audit.get()

        self.is_running = True
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.clear_results()
        mode_str = f"Ventana {int(duration)}s" if duration < 100000 and duration > 0 else ("Monitoreo Continuo" if duration > 0 else "Instantáneo")
        self.log(f"Iniciando escaneo perimetral sobre '{target}' ({len(ports)} puertos) — Modo: {mode_str}...")

        def _on_progress(ports_data: List[Dict[str, Any]], remaining: float):
            rem_text = f"{int(remaining)}s restantes" if duration < 100000 and duration > 0 else "Modo Continuo"
            stable_cnt = sum(1 for p in ports_data if p.get("status") == "ESTABLE")
            self.banner_var.set(
                f"● WATCHDOG ACTIVO ({rem_text}) — Puertos Abiertos: {len(ports_data)} | Estabilidad Alta: {stable_cnt}"
            )
            self.after(0, lambda: self._render_ports(ports_data))

        def _worker():
            start_t = time.time()
            try:
                ip = resolve_host(target)
                self.log(f"Host '{target}' resuelto a IPv4: {ip}")

                if duration > 0:
                    open_ports = scan_ports_timeline(
                        host=ip,
                        ports=ports,
                        duration=duration,
                        interval=2.0,
                        timeout=0.5,
                        progress_callback=_on_progress,
                        stop_check=self.stop_requested,
                    )
                else:
                    open_ports = scan_ports(ip, ports, timeout=0.5, workers=20)
                    for p in open_ports:
                        p["status"] = "ESTABLE"
                        p["stability_percent"] = 100.0

                self.after(0, lambda: self._render_ports(open_ports))

                # OWASP Web Audit if requested
                web_report = None
                web_ports = [p["port"] for p in open_ports if p["port"] in (80, 443, 8080, 8443)]
                if do_web and web_ports:
                    target_web_port = 443 if 443 in web_ports else web_ports[0]
                    self.log(f"Ejecutando auditoría de cabeceras de seguridad OWASP en puerto {target_web_port}...")
                    web_report = audit_http_headers(target, port=target_web_port)

                elapsed = round(time.time() - start_t, 2)
                self.latest_results = {
                    "tool": "NetSentry",
                    "target": target,
                    "target_ip": ip,
                    "duration_seconds": duration,
                    "scan_time": elapsed,
                    "open_ports_count": len(open_ports),
                    "open_ports": open_ports,
                    "web_audit": web_report,
                }
                if self.stop_requested.is_set():
                    self.log(f"Escaneo detenido por el usuario. {len(open_ports)} puertos registrados.")
                else:
                    self.log(f"Escaneo finalizado en {elapsed}s. {len(open_ports)} puertos abiertos.")
                self._update_summary(self.latest_results)
            except Exception as e:
                self.log(f"[ERROR] Error durante el escaneo: {e}")
            finally:
                self.is_running = False
                self.after(0, lambda: self.btn_run.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))
                if self.stop_requested.is_set():
                    self.banner_var.set("⏹ Watchdog de puertos detenido por el operador.")
                else:
                    self.banner_var.set("✔ COMPLETADO — Escaneo y auditoría de servicios finalizados.")

        self.execute_async(_worker, target_duration=duration)

    def stop_analysis(self) -> None:
        super().stop_analysis()
        self.btn_run.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.banner_var.set("⏹ Watchdog de puertos detenido por el operador.")

    def _render_ports(self, open_ports: List[Dict[str, Any]]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        for p in open_ports:
            port_num = p["port"]
            service = p.get("service", SERVICE_NAMES.get(port_num, "Custom"))
            risk = PLAINTEXT_RISK_PORTS.get(port_num, "Cifrado / Estándar")
            tag = "risk_high" if port_num in PLAINTEXT_RISK_PORTS else "clean"

            status = p.get("status", "ESTABLE")
            if status == "INTERMITENTE":
                tag = "status_intermittent"
            elif status == "CAÍDO":
                tag = "status_down"

            stab_str = f"{p.get('stability_percent', 100.0)}% ({status})"
            lat_str = f"{p.get('latency_ms', 0.0)} ms"

            self.tree.insert(
                "", "end",
                values=(
                    port_num,
                    "ABIERTO",
                    stab_str,
                    lat_str,
                    service,
                    p.get("banner") or "-",
                    risk,
                ),
                tags=(tag,)
            )

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INFORME DE SEGURIDAD DE PUERTOS Y CABECERAS OWASP — NETSENTRY",
                "=========================================================================",
                f" Objetivo Auditado:       {data.get('target')} ({data.get('target_ip')})",
                f" Tiempo de Observación:   {data.get('scan_time')} segundos",
                f" Puertos Abiertos:        {data.get('open_ports_count')}",
                "",
                "--- PUERTOS DETECTADOS Y RIESGO ---",
            ]
            for p in data.get("open_ports", []):
                risk = PLAINTEXT_RISK_PORTS.get(p["port"], "Cifrado / Seguro")
                lines.append(f"  • Puerto {p['port']:<5} ({p.get('service', 'Custom'):<12}) | Estabilidad: {p.get('stability_percent', 100)}% -> {risk}")

            web = data.get("web_audit")
            if web:
                lines.append("\n--- AUDITORÍA DE CABECERAS DE SEGURIDAD WEB (OWASP) ---")
                lines.append(f" URL Web:          {web.get('url')}")
                lines.append(f" Calificación:     Grado [{web.get('grade')}] ({web.get('score_fraction')})")
                lines.append(f" Cabeceras Activas: {', '.join(web.get('present_headers', [])) or 'Ninguna'}")
                lines.append(f" Cabeceras Faltantes: {', '.join(web.get('missing_headers', [])) or 'Ninguna'}")

            lines.append("\n=========================================================================\n")
            self.summary_text.insert("end", "\n".join(lines))
        self.after(0, _render)

    def clear_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.console_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")
        self.latest_results = None
        self.set_status("Listo.")
