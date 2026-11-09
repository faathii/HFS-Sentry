"""Independent Desktop Window for LogSentinel."""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from sentry.tools.logsentinel import (
    analyze_log_file,
    evaluate_threats,
    generate_block_script,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class LogSentinelWindow(BaseToolWindow):
    """LogSentinel Independent GUI Application."""

    tool_id = "logsentinel"
    tool_title = "LogSentinel — Log Forensic Analyzer & Active IDS"
    tool_category = "Forensic & Incident Response"
    tool_version = "1.0.0"
    icon_filename = "logsentinel.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct log file picker, threshold controls and analysis buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        ttk.Label(row1, text="Archivo de Registro (Log):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_file = ttk.Entry(row1, width=45)
        # Default to bundled example log if present
        default_log = os.path.join("examples", "sample_auth.log")
        if os.path.isfile(default_log):
            self.entry_file.insert(0, default_log)
        self.entry_file.pack(side="left", padx=(0, 6))

        btn_browse = ttk.Button(row1, text="📁 Examinar...", command=self._browse_log_file)
        btn_browse.pack(side="left", padx=(0, 16))

        ttk.Label(row1, text="Umbral Fallos SSH:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_thresh = ttk.Spinbox(row1, from_=1, to=100, width=5)
        self.spin_thresh.set("5")
        self.spin_thresh.pack(side="left", padx=(0, 16))

        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(8, 2))

        btn_sample_access = ttk.Button(
            row2, text="Cargar Access Log de Ejemplo", command=self._load_sample_access
        )
        btn_sample_access.pack(side="left", padx=(0, 10))

        self.btn_gen_fw = ttk.Button(
            row2, text="🛡️ Generar Script Firewall (.sh)", command=self.export_firewall_script
        )
        self.btn_gen_fw.pack(side="left", padx=(0, 10))

        self.btn_run = ttk.Button(row2, text="▶ Analizar Registro", style="Primary.TButton", command=self.start_analysis)
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
            title="Seleccionar Archivo de Registro (auth.log, access.log, secure)",
            filetypes=[("Archivos Log / Texto", "*.log *.txt"), ("Todos los archivos", "*.*")]
        )
        if path:
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, path)

    def _load_sample_access(self) -> None:
        path = os.path.join("examples", "sample_access.log")
        if os.path.isfile(path):
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, path)
            self.start_analysis()
        else:
            messagebox.showwarning("Aviso", "No se encontró el archivo 'examples/sample_access.log'.")

    def start_analysis(self) -> None:
        """Parse log file and correlate threats."""
        log_path = self.entry_file.get().strip()
        if not log_path or not os.path.isfile(log_path):
            messagebox.showerror("Archivo No Válido", f"El archivo de registro no existe:\n{log_path}")
            return

        threshold = int(self.spin_thresh.get())
        self.clear_results()
        self.log(f"Iniciando análisis forense sobre '{log_path}' con umbral SSH={threshold}...")

        def _worker():
            collector = analyze_log_file(log_path)
            threats = evaluate_threats(collector, ssh_threshold=threshold)
            self.log(f"Análisis completado. Amenazas identificadas: {len(threats)}")

            for t in threats:
                sev = t["severity"]
                tag = f"sev_{sev.lower()}"
                sample = t["sample_payloads"][0] if t["sample_payloads"] else "-"
                total_att = t["ssh_failed_count"] + t["traversal_count"] + t["exploit_attempts"]
                self.after(0, lambda tr=t, tg=tag, s=sample, tot=total_att: self.tree.insert(
                    "", "end", values=(tr["severity"], tr["ip"], " | ".join(tr["reasons"]), tot, s), tags=(tg,)
                ))
                self.log(f"[{t['severity']}] IP {t['ip']} -> {' | '.join(t['reasons'])}")

            self.latest_results = {
                "tool": "LogSentinel",
                "log_file": log_path,
                "threat_count": len(threats),
                "threats": threats,
            }
            self._update_summary(self.latest_results)

        self.execute_async(_worker)

    def export_firewall_script(self) -> None:
        """Generate and save block_threats.sh."""
        if not self.latest_results or not self.latest_results.get("threats"):
            messagebox.showinfo("Sin Amenazas", "Primero realice un análisis que identifique amenazas para generar el script de cortafuegos.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".sh",
            filetypes=[("Scripts Bash", "*.sh"), ("Todos los archivos", "*.*")],
            title="Guardar Script de Cortafuegos (UFW / iptables)",
            initialfile="block_threats.sh"
        )
        if path:
            generate_block_script(self.latest_results["threats"], output_file=path)
            messagebox.showinfo("Script Generado", f"Script de cortafuegos listo para Linux:\n{path}\n\nComando: sudo bash {os.path.basename(path)}")

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INFORME DE ANÁLISIS FORENSE E INTRUSIÓN — LOGSENTINEL",
                "=========================================================================",
                f" Archivo Analizado:       {data['log_file']}",
                f" Amenazas Identificadas:  {data['threat_count']}",
                "",
                "--- VECTORES DE ATAQUE IDENTIFICADOS ---",
            ]
            if not data["threats"]:
                lines.append("  [✔] Estado óptimo: No se encontraron patrones maliciosos que superen los umbrales.")
            else:
                for t in data["threats"]:
                    lines.append(f"  • IP: {t['ip']} [{t['severity']}]")
                    for r in t["reasons"]:
                        lines.append(f"      └── {r}")

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
