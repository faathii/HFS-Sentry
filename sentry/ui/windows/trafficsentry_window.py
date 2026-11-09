"""Independent Desktop Window for TrafficSentry."""

import tkinter as tk
from tkinter import ttk
from typing import Optional

from sentry.tools.trafficsentry import audit_active_sockets
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class TrafficSentryWindow(BaseToolWindow):
    """TrafficSentry Independent GUI Application."""

    tool_id = "trafficsentry"
    tool_title = "TrafficSentry — Active Sockets & Port Exposure Auditor"
    tool_category = "Host Security & Network"
    tool_version = "1.0.0"
    icon_filename = "hfs_sentry.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct filter options, search and refresh buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        self.var_listen_only = tk.BooleanVar(value=True)
        self.chk_listen = ttk.Checkbutton(row1, text="Solo Puertos Escuchando (LISTEN)", variable=self.var_listen_only)
        self.chk_listen.pack(side="left", padx=(0, 16))

        ttk.Label(row1, text="Filtrar por Puerto o IP:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_filter = ttk.Entry(row1, width=20)
        self.entry_filter.pack(side="left", padx=(0, 16))
        self.entry_filter.bind("<KeyRelease>", lambda e: self._apply_search_filter())

        self.btn_run = ttk.Button(row1, text="🔄 Auditar Sockets Activos", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for active system sockets."""
        columns = ("proto", "local", "foreign", "state", "pid", "risk", "desc")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("proto", text="PROTO")
        self.tree.heading("local", text="DIRECCIÓN LOCAL (PUERTO)")
        self.tree.heading("foreign", text="DIRECCIÓN REMOTA")
        self.tree.heading("state", text="ESTADO")
        self.tree.heading("pid", text="PID")
        self.tree.heading("risk", text="NIVEL DE RIESGO")
        self.tree.heading("desc", text="DIAGNÓSTICO PERIMETRAL")

        self.tree.column("proto", width=70, anchor="center")
        self.tree.column("local", width=200, anchor="w")
        self.tree.column("foreign", width=180, anchor="w")
        self.tree.column("state", width=110, anchor="center")
        self.tree.column("pid", width=70, anchor="center")
        self.tree.column("risk", width=130, anchor="center")
        self.tree.column("desc", width=340, anchor="w")

        self.tree.tag_configure("risk_crit", foreground=COLORS["accent_red"])
        self.tree.tag_configure("risk_high", foreground=COLORS["accent_red"])
        self.tree.tag_configure("risk_med", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("risk_clean", foreground=COLORS["accent_green"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def start_analysis(self) -> None:
        listen_only = self.var_listen_only.get()
        self.clear_results()
        self.log(f"Inspeccionando sockets de red activos en el sistema operativo...")

        def _worker():
            try:
                sockets = audit_active_sockets(listening_only=listen_only)
                self.all_sockets = sockets
                self.latest_results = {
                    "tool": "TrafficSentry",
                    "total_sockets": len(sockets),
                    "sockets": sockets,
                }
                self.log(f"Auditoría completada. {len(sockets)} sockets activos registrados.")
                self.after(0, self._apply_search_filter)
                self._update_summary(self.latest_results)
            except Exception as e:
                self.log(f"[ERROR] Falló la lectura de sockets: {e}")

        self.execute_async(_worker)

    def _apply_search_filter(self) -> None:
        """Filter table rows based on search input."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.entry_filter.get().strip().lower()
        sockets = getattr(self, "all_sockets", [])

        for s in sockets:
            local_str = f"{s['local_address']}:{s['local_port']}"
            if query and query not in local_str.lower() and query not in str(s["pid"]) and query not in s["service"].lower():
                continue

            risk = s["risk_level"]
            tag = f"risk_{risk.lower()}"
            self.tree.insert(
                "", "end",
                values=(s["protocol"], local_str, f"{s['foreign_address']}:{s['foreign_port']}", s["state"], s["pid"], risk, s["risk_description"]),
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

            lines = [
                "=========================================================================",
                " INFORME DE EXPOSICIÓN DE PUERTOS Y SOCKETS — TRAFFICSENTRY",
                "=========================================================================",
                f" Total Sockets Analizados: {len(sockets)}",
                f" Puertos en Localhost:    {clean} (Seguros / 127.0.0.1)",
                f" Exposición 0.0.0.0 Media: {med}",
                f" Exposición Alta / Crítica: {crit + high} (!)",
                "",
                "--- RESUMEN DE SERVICIOS SENSIBLES ---",
            ]
            for s in sockets:
                if s["risk_level"] in ("CRITICAL", "HIGH"):
                    lines.append(f"  • [{s['risk_level']}] Puerto {s['local_port']} ({s['service']}) en {s['local_address']} -> {s['risk_description']}")

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
