"""Independent Desktop Window for LogSentinel with responsive layout and live stopwatch."""

import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from sentry.tools.logsentinel import (
    analyze_log_file,
    evaluate_threats,
    generate_block_script,
    watch_log_timeline,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS, resolve_resource_path


class LogSentinelWindow(BaseToolWindow):
    """LogSentinel Independent GUI Application with Live Observation Window."""

    tool_id = "logsentinel"
    tool_title = "LogSentinel — Log Forensic Analyzer & Active IDS"
    tool_category = "Forensic & Incident Response"
    tool_version = "1.1.0"
    icon_filename = "logsentinel.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct log file picker, duration controls, threshold and responsive action buttons."""
        self.is_running = False
        self.current_threats: List[Dict[str, Any]] = []

        # Row 1: Target parameters and filters
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=(2, 6))

        ttk.Label(row1, text="Archivo Log:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_file = ttk.Entry(row1, width=28)
        default_log = resolve_resource_path(os.path.join("examples", "sample_auth.log"))
        if os.path.isfile(default_log):
            self.entry_file.insert(0, default_log)
        self.entry_file.pack(side="left", padx=(0, 6))

        btn_browse = ttk.Button(row1, text="📁 Examinar...", command=self._browse_log_file)
        btn_browse.pack(side="left", padx=(0, 14))

        ttk.Label(row1, text="Ventana:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.combo_duration = ttk.Combobox(
            row1,
            values=[
                "⚡ Archivo Estático (Instantáneo)",
                "⏱️ Ventana 30s (Vigilante en Vivo)",
                "⏱️ Ventana 60s",
                "🔄 Monitoreo Continuo (Live Tail)",
            ],
            state="readonly",
            width=24,
        )
        self.combo_duration.current(0)
        self.combo_duration.pack(side="left", padx=(0, 14))

        ttk.Label(row1, text="Umbral SSH:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_thresh = ttk.Spinbox(row1, from_=1, to=100, width=4)
        self.spin_thresh.set("5")
        self.spin_thresh.pack(side="left", padx=(0, 6))

        # Row 2: Action toolbar (Buttons & Banner guaranteed visible)
        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(2, 2))

        btn_sample = ttk.Button(row2, text="Muestra Access.log", command=self._load_sample_access)
        btn_sample.pack(side="left", padx=(0, 6))

        self.btn_gen_fw = ttk.Button(row2, text="🛡️ Firewall (.sh)", command=self.export_firewall_script)
        self.btn_gen_fw.pack(side="left", padx=(0, 8))

        ttk.Label(row2, text="Filtrar:", style="Card.TLabel").pack(side="left", padx=(0, 4))
        self.entry_filter = ttk.Entry(row2, width=14)
        self.entry_filter.pack(side="left", padx=(0, 8))
        self.entry_filter.bind("<KeyRelease>", lambda e: self._render_threats())

        self.banner_var = tk.StringVar(value="Listo para auditar registros del sistema.")
        self.lbl_banner = ttk.Label(row2, textvariable=self.banner_var, font=FONTS["code_small"], foreground=COLORS["accent_cyan"])
        self.lbl_banner.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_stop = ttk.Button(row2, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=(4, 0))

        self.btn_run = ttk.Button(row2, text="▶ Analizar / Vigilar Log", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for detected intrusion threats."""
        columns = ("severity", "ip", "vectors", "attempts", "sample")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("severity", text="SEVERIDAD")
        self.tree.heading("ip", text="IP ATACANTE")
        self.tree.heading("vectors", text="PATRONES DE INTRUSIÓN DETECTADOS")
        self.tree.heading("attempts", text="INTENTOS")
        self.tree.heading("sample", text="MUESTRA DEL PAYLOAD / AGENTE")

        self.tree.column("severity", width=100, anchor="center")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("vectors", width=280, anchor="w")
        self.tree.column("attempts", width=80, anchor="center")
        self.tree.column("sample", width=260, anchor="w")

        self.tree.tag_configure("sev_crit", foreground=COLORS["accent_red"])
        self.tree.tag_configure("sev_high", foreground=COLORS["accent_red"])
        self.tree.tag_configure("sev_med", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("sev_low", foreground=COLORS["text_secondary"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _browse_log_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Seleccionar Archivo de Registro",
            filetypes=[("Log files (*.log, *.txt)", "*.log;*.txt"), ("All files", "*.*")],
        )
        if path:
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, path)

    def _load_sample_access(self) -> None:
        path = resolve_resource_path(os.path.join("examples", "sample_access.log"))
        if os.path.isfile(path):
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, path)
            self.log(f"Cargado archivo de prueba: {path}")
        else:
            messagebox.showwarning("No Encontrado", f"No se encontró '{path}'.")

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

        path = self.entry_file.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Archivo No Válido", "Por favor seleccione un archivo de log existente.")
            return

        duration = self._get_selected_duration()
        try:
            ssh_thresh = max(1, int(self.spin_thresh.get()))
        except Exception:
            ssh_thresh = 5

        self.is_running = True
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.clear_results()
        mode_str = f"Ventana {int(duration)}s" if duration < 100000 and duration > 0 else ("Monitoreo Continuo" if duration > 0 else "Estático")
        self.log(f"Iniciando análisis forense sobre '{path}' (Umbral: {ssh_thresh}) — Modo: {mode_str}...")

        def _on_progress(threats: List[Dict[str, Any]], remaining: float, lines_read: int):
            self.current_threats = threats
            rem_text = f"{int(remaining)}s restantes" if duration < 100000 and duration > 0 else "Modo Continuo"
            self.banner_var.set(
                f"● VIGILANDO LOG ({rem_text}) — Líneas Leídas: {lines_read:,} | Amenazas Detectadas: {len(threats)}"
            )
            self.after(0, self._render_threats)

        def _worker():
            start_t = time.time()
            try:
                if duration > 0:
                    threats = watch_log_timeline(
                        file_path=path,
                        duration=duration,
                        ssh_threshold=ssh_thresh,
                        progress_callback=_on_progress,
                        stop_check=self.stop_requested,
                    )
                else:
                    collector = analyze_log_file(path)
                    threats = evaluate_threats(collector, ssh_threshold=ssh_thresh)

                self.current_threats = threats
                elapsed = round(time.time() - start_t, 2)
                self.latest_results = {
                    "tool": "LogSentinel",
                    "file_analyzed": path,
                    "duration_seconds": duration,
                    "total_threats": len(threats),
                    "threats": threats,
                }
                if self.stop_requested.is_set():
                    self.log(f"Vigilancia de log detenida por el usuario. {len(threats)} amenazas correlacionadas.")
                else:
                    self.log(f"Análisis completado en {elapsed}s. {len(threats)} vectores hostiles identificados.")
                self.after(0, self._render_threats)
                self._update_summary(self.latest_results, elapsed)
            except Exception as e:
                self.log(f"[ERROR] Error al procesar log: {e}")
            finally:
                self.is_running = False
                self.after(0, lambda: self.btn_run.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))
                if self.stop_requested.is_set():
                    self.banner_var.set("⏹ Vigilante de log detenido por el operador.")
                else:
                    self.banner_var.set(f"✔ COMPLETADO — {len(self.current_threats)} atacantes correlacionados en el registro.")

        self.execute_async(_worker, target_duration=duration)

    def stop_analysis(self) -> None:
        super().stop_analysis()
        self.btn_run.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.banner_var.set("⏹ Vigilante de log detenido por el operador.")

    def _render_threats(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.entry_filter.get().strip().lower()

        for t in getattr(self, "current_threats", []):
            ip = t["ip"]
            reasons_str = " | ".join(t["reasons"])
            sample = t["sample_payloads"][0] if t["sample_payloads"] else "-"
            sev = t["severity"]

            if query:
                match = (
                    query in ip.lower()
                    or query in reasons_str.lower()
                    or query in sample.lower()
                    or query in sev.lower()
                )
                if not match:
                    continue

            tag = f"sev_{sev.lower()}"
            total_attempts = t["ssh_failed_count"] + t["traversal_count"] + t["exploit_attempts"]
            self.tree.insert(
                "", "end",
                values=(sev, ip, reasons_str, total_attempts, sample),
                tags=(tag,)
            )

    def _update_summary(self, data: dict, elapsed: float) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            threats = data.get("threats", [])
            lines = [
                "=========================================================================",
                " INFORME DE RESPUESTA A INCIDENTES Y FORENSE — LOGSENTINEL",
                "=========================================================================",
                f" Archivo Analizado:       {data.get('file_analyzed')}",
                f" Tiempo de Observación:   {elapsed} segundos",
                f" Amenazas Identificadas:  {len(threats)} IPs hostiles",
                "",
                "--- DESGLOSE POR SEVERIDAD ---",
            ]
            crit = sum(1 for t in threats if t["severity"] == "CRITICAL")
            high = sum(1 for t in threats if t["severity"] == "HIGH")
            med = sum(1 for t in threats if t["severity"] == "MEDIUM")
            lines.append(f"  • CRITICAL (Exploits / RCE / SQLi): {crit}")
            lines.append(f"  • HIGH (Fuerza Bruta / Traversal):  {high}")
            lines.append(f"  • MEDIUM (Sondeos automatizados):   {med}")

            lines.append("\n--- IPS BLOQUEABLES SUGERIDAS ---")
            for t in threats:
                lines.append(f"  • {t['ip']:<15} [{t['severity']}] -> {', '.join(t['reasons'])}")

            lines.append("\n=========================================================================\n")
            self.summary_text.insert("end", "\n".join(lines))
        self.after(0, _render)

    def export_firewall_script(self) -> None:
        threats = getattr(self, "current_threats", [])
        if not threats:
            messagebox.showinfo("Sin Amenazas", "No hay amenazas detectadas para exportar reglas de firewall.")
            return

        dest = filedialog.asksaveasfilename(
            title="Guardar Script Firewall",
            defaultextension=".sh",
            initialfile="block_threats.sh",
            filetypes=[("Shell Script (*.sh)", "*.sh"), ("All files", "*.*")],
        )
        if dest:
            generate_block_script(threats, output_file=dest)
            messagebox.showinfo("Script Creado", f"Reglas de bloqueo IPTables/UFW exportadas con éxito en:\n{dest}")

    def clear_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.console_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")
        self.latest_results = None
        self.set_status("Listo.")
