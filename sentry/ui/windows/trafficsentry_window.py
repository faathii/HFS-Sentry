"""Independent Desktop Window for TrafficSentry."""

import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional

from sentry.tools.trafficsentry import audit_active_sockets, audit_sockets_timeline
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class TrafficSentryWindow(BaseToolWindow):
    """TrafficSentry Independent GUI Application."""

    tool_id = "trafficsentry"
    tool_title = "TrafficSentry — Active Sockets & Port Exposure Auditor"
    tool_category = "Host Security & Network"
    tool_version = "1.1.0"
    icon_filename = "hfs_sentry.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct filter options, duration controls, search and refresh buttons."""
        self.stop_requested = False
        self.is_running = False
        self.all_sockets: List[Dict[str, Any]] = []

        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=4)

        # Duración / Modo de Ventana Temporal
        ttk.Label(row1, text="Ventana Temporal:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.combo_duration = ttk.Combobox(
            row1,
            values=[
                "⏱️ Ventana 30s (Recomendado)",
                "⚡ Instantáneo (1s)",
                "⏱️ Ventana 10s",
                "⏱️ Ventana 60s",
                "🔄 Monitoreo Continuo (En Vivo)",
            ],
            state="readonly",
            width=28,
        )
        self.combo_duration.current(0)
        self.combo_duration.pack(side="left", padx=(0, 16))

        # Checkbox Solo Escuchando
        self.var_listen_only = tk.BooleanVar(value=False)
        self.chk_listen = ttk.Checkbutton(row1, text="Solo Puertos Escuchando (LISTEN)", variable=self.var_listen_only)
        self.chk_listen.pack(side="left", padx=(0, 16))

        # Buscador en Tiempo Real
        ttk.Label(row1, text="Filtrar (IP, Proceso, Puerto):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_filter = ttk.Entry(row1, width=22)
        self.entry_filter.pack(side="left", padx=(0, 16))
        self.entry_filter.bind("<KeyRelease>", lambda e: self._apply_search_filter())

        # Botón Detener
        self.btn_stop = ttk.Button(row1, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=4)

        # Botón Iniciar
        self.btn_run = ttk.Button(row1, text="▶ Iniciar Auditoría Temporal", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

        # Indicador de estado de captura temporal
        self.banner_var = tk.StringVar(value="Listo para auditar en ventana de tiempo acumulativo.")
        self.lbl_banner = ttk.Label(parent, textvariable=self.banner_var, font=FONTS["code_sm"], foreground=COLORS["accent_cyan"])
        self.lbl_banner.pack(anchor="w", padx=4, pady=(0, 4))

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for active system sockets with process names and durations."""
        columns = ("proto", "proc", "local", "foreign", "state", "dur", "first_seen", "pid", "risk", "desc")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("proto", text="PROTO")
        self.tree.heading("proc", text="PROCESO")
        self.tree.heading("local", text="DIRECCIÓN LOCAL (PUERTO)")
        self.tree.heading("foreign", text="DIRECCIÓN REMOTA")
        self.tree.heading("state", text="ESTADO")
        self.tree.heading("dur", text="DURACIÓN")
        self.tree.heading("first_seen", text="INICIO")
        self.tree.heading("pid", text="PID")
        self.tree.heading("risk", text="RIESGO")
        self.tree.heading("desc", text="DIAGNÓSTICO PERIMETRAL")

        self.tree.column("proto", width=65, anchor="center")
        self.tree.column("proc", width=120, anchor="w")
        self.tree.column("local", width=180, anchor="w")
        self.tree.column("foreign", width=160, anchor="w")
        self.tree.column("state", width=110, anchor="center")
        self.tree.column("dur", width=80, anchor="center")
        self.tree.column("first_seen", width=85, anchor="center")
        self.tree.column("pid", width=65, anchor="center")
        self.tree.column("risk", width=100, anchor="center")
        self.tree.column("desc", width=280, anchor="w")

        self.tree.tag_configure("risk_crit", foreground=COLORS["accent_red"])
        self.tree.tag_configure("risk_high", foreground=COLORS["accent_red"])
        self.tree.tag_configure("risk_med", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("risk_clean", foreground=COLORS["accent_green"])
        self.tree.tag_configure("risk_low", foreground=COLORS["text_primary"])
        self.tree.tag_configure("status_closed", foreground="#64748b")

        scroll_y = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

    def _get_selected_duration(self) -> float:
        val = self.combo_duration.get()
        if "30s" in val:
            return 30.0
        elif "10s" in val:
            return 10.0
        elif "60s" in val:
            return 60.0
        elif "Continuo" in val:
            return 999999.0
        return 0.0

    def start_analysis(self) -> None:
        if self.is_running:
            return

        self.is_running = True
        self.stop_requested = False
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        duration = self._get_selected_duration()
        listen_only = self.var_listen_only.get()

        self.clear_results()
        mode_str = f"{int(duration)}s" if duration < 100000 else "Monitoreo Continuo"
        if duration == 0:
            mode_str = "Instantáneo (1s)"
        self.log(f"Iniciando auditoría perimetral de sockets — Ventana: {mode_str}...")

        def _on_progress(cumulative_sockets: List[Dict[str, Any]], remaining: float):
            self.all_sockets = cumulative_sockets
            active_count = sum(1 for s in cumulative_sockets if s.get("timeline_status") == "ACTIVO")
            closed_count = sum(1 for s in cumulative_sockets if s.get("timeline_status") == "CERRADO")

            rem_text = f"{int(remaining)}s restantes" if duration < 100000 and duration > 0 else "Modo Continuo Activo"
            self.banner_var.set(
                f"● MONITOREANDO ({rem_text}) — Total Acumulado: {len(cumulative_sockets)} | Activos: {active_count} | Efímeros/Cerrados: {closed_count}"
            )
            self.after(0, self._apply_search_filter)

        def _worker():
            try:
                sockets = audit_sockets_timeline(
                    duration=duration,
                    interval=1.0,
                    listening_only=listen_only,
                    progress_callback=_on_progress,
                    stop_check=lambda: self.stop_requested,
                )
                self.all_sockets = sockets
                self.latest_results = {
                    "tool": "TrafficSentry",
                    "duration_seconds": duration,
                    "total_sockets": len(sockets),
                    "sockets": sockets,
                }
                self.log(f"Auditoría finalizada. {len(sockets)} eventos de red registrados en la ventana de observación.")
                self.after(0, self._apply_search_filter)
                self._update_summary(self.latest_results)
            except Exception as e:
                self.log(f"[ERROR] Error durante la auditoría de sockets: {e}")
            finally:
                self.is_running = False
                self.after(0, lambda: self.btn_run.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))
                self.banner_var.set(f"✔ COMPLETADO — {len(self.all_sockets)} sockets capturados en la ventana de tiempo.")

        self.execute_async(_worker)

    def stop_analysis(self) -> None:
        if self.is_running:
            self.stop_requested = True
            self.log("[*] Solicitud de parada enviada. Finalizando recolección...")
            self.btn_stop.configure(state="disabled")

    def _apply_search_filter(self) -> None:
        """Filter table rows based on search input and render timeline status."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.entry_filter.get().strip().lower()
        sockets = getattr(self, "all_sockets", [])

        for s in sockets:
            local_str = f"{s['local_address']}:{s['local_port']}"
            remote_str = f"{s['foreign_address']}:{s['foreign_port']}" if s['foreign_port'] != "-" else s['foreign_address']
            proc_name = s.get("process_name", "Desconocido")
            pid_str = str(s["pid"])
            service_str = s.get("service", "")
            risk = s["risk_level"]
            status = s.get("timeline_status", s.get("state", "ACTIVO"))

            # Filter matching
            if query:
                match = (
                    query in local_str.lower()
                    or query in remote_str.lower()
                    or query in proc_name.lower()
                    or query in pid_str
                    or query in service_str.lower()
                    or query in risk.lower()
                )
                if not match:
                    continue

            tag = f"risk_{risk.lower()}"
            if status == "CERRADO":
                tag = "status_closed"
                status_display = "○ CERRADO"
            elif "LISTEN" in status.upper():
                status_display = "LISTEN"
            else:
                status_display = "● ACTIVO"

            dur_str = f"{s.get('duration_sec', 0.0)}s"
            first_seen_str = s.get("first_seen", "-")

            self.tree.insert(
                "", "end",
                values=(
                    s["protocol"],
                    proc_name,
                    local_str,
                    remote_str,
                    status_display,
                    dur_str,
                    first_seen_str,
                    pid_str,
                    risk,
                    s["risk_description"],
                ),
                tags=(tag,)
            )

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            sockets = data.get("sockets", [])
            crit = sum(1 for s in sockets if s["risk_level"] == "CRITICAL")
            high = sum(1 for s in sockets if s["risk_level"] == "HIGH")
            med = sum(1 for s in sockets if s["risk_level"] == "MEDIUM")
            clean = sum(1 for s in sockets if s["risk_level"] == "CLEAN")
            active = sum(1 for s in sockets if s.get("timeline_status") == "ACTIVO")
            closed = sum(1 for s in sockets if s.get("timeline_status") == "CERRADO")

            lines = [
                "=========================================================================",
                " INFORME DE EXPOSICIÓN DE PUERTOS Y SOCKETS TEMPORAL — TRAFFICSENTRY",
                "=========================================================================",
                f" Ventana de Observación:  {data.get('duration_seconds', 0)} segundos",
                f" Total Conexiones Vistas: {len(sockets)}",
                f" Conexiones Activas:      {active}",
                f" Conexiones Efímeras:     {closed} (Cerradas durante la ventana)",
                f" Puertos en Localhost:    {clean} (Seguros / 127.0.0.1)",
                f" Exposición 0.0.0.0 Media:{med}",
                f" Exposición Alta/Crítica: {crit + high} (!)",
                "",
                "--- TOP PROCESOS DETECTADOS ---",
            ]

            proc_counts = {}
            for s in sockets:
                p = s.get("process_name", "Desconocido")
                proc_counts[p] = proc_counts.get(p, 0) + 1

            for p, cnt in sorted(proc_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"  • {p:<25} ({cnt} conexiones)")

            lines.append("\n--- RESUMEN DE SERVICIOS SENSIBLES Y RIESGOS ---")
            risky = [s for s in sockets if s["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM")]
            if risky:
                for s in risky:
                    lines.append(f"  • [{s['risk_level']}] {s.get('process_name')} (PID {s['pid']}) en {s['local_address']}:{s['local_port']} -> {s['risk_description']}")
            else:
                lines.append("  ✔ No se detectaron servicios de riesgo expuestos en interfaces públicas.")

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
