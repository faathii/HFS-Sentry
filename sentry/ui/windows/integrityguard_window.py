"""Independent Desktop Window for IntegrityGuard (FIM) with responsive layout and live stopwatch."""

import json
import os
import platform
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from sentry.tools.integrityguard import (
    DEFAULT_TARGET_PATHS,
    collect_file_metadata,
    generate_baseline,
    verify_integrity,
    watch_integrity_timeline,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class IntegrityGuardWindow(BaseToolWindow):
    """IntegrityGuard Independent GUI Application with Real-Time Sentinel."""

    tool_id = "integrityguard"
    tool_title = "IntegrityGuard — Host File Integrity Monitor (FIM)"
    tool_category = "HIDS & Forensics"
    tool_version = "1.1.0"
    icon_filename = "integrityguard.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct baseline file picker, target manager, duration controls and responsive buttons."""
        self.is_running = False

        # Row 1: Targets and baseline file
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=(2, 6))

        ttk.Label(row1, text="Línea Base (JSON):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_baseline = ttk.Entry(row1, width=22)
        self.entry_baseline.insert(0, "sentry_baseline.json")
        self.entry_baseline.pack(side="left", padx=(0, 6))

        btn_browse_base = ttk.Button(row1, text="📁 Examinar...", command=self._browse_baseline)
        btn_browse_base.pack(side="left", padx=(0, 12))

        ttk.Label(row1, text="Objetivos:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_target = ttk.Entry(row1, width=28)
        sys_os = platform.system()
        def_target = DEFAULT_TARGET_PATHS.get(sys_os, [DEFAULT_TARGET_PATHS["Linux"][0]])[0]
        self.entry_target.insert(0, def_target)
        self.entry_target.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_add_file = ttk.Button(row1, text="+ Archivo", command=self._add_file_target)
        btn_add_file.pack(side="left", padx=2)

        btn_add_dir = ttk.Button(row1, text="+ Carpeta", command=self._add_dir_target)
        btn_add_dir.pack(side="left", padx=2)

        # Row 2: Action toolbar (Buttons & Banner guaranteed visible)
        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(2, 2))

        ttk.Label(row2, text="Ventana:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.combo_duration = ttk.Combobox(
            row2,
            values=[
                "⚡ Verificación Instantánea",
                "⏱️ Ventana 30s (Centinela Activo)",
                "⏱️ Ventana 60s",
                "🔄 Monitoreo Continuo",
            ],
            state="readonly",
            width=26,
        )
        self.combo_duration.current(0)
        self.combo_duration.pack(side="left", padx=(0, 10))

        self.btn_init = ttk.Button(row2, text="➕ Crear Línea Base (SHA-256)", command=self._create_baseline)
        self.btn_init.pack(side="left", padx=(0, 10))

        ttk.Label(row2, text="Filtrar:", style="Card.TLabel").pack(side="left", padx=(0, 4))
        self.entry_filter = ttk.Entry(row2, width=14)
        self.entry_filter.pack(side="left", padx=(0, 10))
        self.entry_filter.bind("<KeyRelease>", lambda e: self._render_results(getattr(self, "latest_results", {})))

        self.banner_var = tk.StringVar(value="Listo para auditar la integridad de archivos críticos.")
        self.lbl_banner = ttk.Label(row2, textvariable=self.banner_var, font=FONTS["code_small"], foreground=COLORS["accent_cyan"])
        self.lbl_banner.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_stop = ttk.Button(row2, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=(4, 0))

        self.btn_check = ttk.Button(row2, text="🛡️ Verificar Integridad", style="Primary.TButton", command=self.start_analysis)
        self.btn_check.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for file status and cryptographic hashes."""
        columns = ("path", "status", "hash", "size", "mtime")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("path", text="RUTA DEL ARCHIVO CRÍTICO")
        self.tree.heading("status", text="ESTADO DE INTEGRIDAD")
        self.tree.heading("hash", text="FIRMA CRIPTOGRÁFICA SHA-256")
        self.tree.heading("size", text="TAMAÑO")
        self.tree.heading("mtime", text="ÚLTIMA MODIFICACIÓN")

        self.tree.column("path", width=300, anchor="w")
        self.tree.column("status", width=140, anchor="center")
        self.tree.column("hash", width=260, anchor="w")
        self.tree.column("size", width=80, anchor="center")
        self.tree.column("mtime", width=160, anchor="center")

        self.tree.tag_configure("status_intact", foreground=COLORS["accent_green"])
        self.tree.tag_configure("status_modified", foreground=COLORS["accent_red"])
        self.tree.tag_configure("status_deleted", foreground=COLORS["accent_yellow"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _browse_baseline(self) -> None:
        path = filedialog.askopenfilename(
            title="Seleccionar Base de Datos Baseline",
            filetypes=[("JSON files (*.json)", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.entry_baseline.delete(0, "end")
            self.entry_baseline.insert(0, path)

    def _add_file_target(self) -> None:
        f = filedialog.askopenfilename(title="Seleccionar Archivo para Monitorear")
        if f:
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, f)

    def _add_dir_target(self) -> None:
        d = filedialog.askdirectory(title="Seleccionar Carpeta para Monitorear Recursivamente")
        if d:
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, d)

    def _get_selected_duration(self) -> float:
        val = self.combo_duration.get()
        if "30s" in val:
            return 30.0
        elif "60s" in val:
            return 60.0
        elif "Continuo" in val:
            return 999999.0
        return 0.0

    def _create_baseline(self) -> None:
        target = self.entry_target.get().strip()
        baseline_file = self.entry_baseline.get().strip()
        if not target or not baseline_file:
            messagebox.showerror("Error", "Especifique el objetivo y el archivo de base de datos JSON.")
            return

        self.log(f"Generando firmas criptográficas SHA-256 para '{target}'...")
        try:
            baseline = generate_baseline([target], baseline_file)
            count = len(baseline["files"])
            self.log(f"[ÉXITO] Línea base creada: {count} archivos sellados en '{baseline_file}'.")
            messagebox.showinfo("Línea Base Creada", f"Se han sellado criptográficamente {count} archivos en:\n{baseline_file}")
        except Exception as e:
            self.log(f"[ERROR] Error al crear baseline: {e}")
            messagebox.showerror("Error", str(e))

    def start_analysis(self) -> None:
        if self.is_running:
            return

        baseline_file = self.entry_baseline.get().strip()
        target = self.entry_target.get().strip()
        duration = self._get_selected_duration()

        self.is_running = True
        self.btn_check.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.clear_results()
        mode_str = f"Ventana {int(duration)}s" if duration < 100000 and duration > 0 else ("Monitoreo Continuo" if duration > 0 else "Instantáneo")
        self.log(f"Iniciando verificación criptográfica FIM — Modo: {mode_str}...")

        def _on_progress(verif: Dict[str, Any], remaining: float):
            rem_text = f"{int(remaining)}s restantes" if duration < 100000 and duration > 0 else "Modo Continuo"
            tampered = verif.get("tampered", False)
            mod_count = len(verif.get("modified", []))
            del_count = len(verif.get("deleted", []))

            status_icon = "⚠️ ALTERACIÓN DETECTADA" if tampered else "✔ ÍNTEGRO"
            self.banner_var.set(
                f"● VIGILANDO INTEGRIDAD ({rem_text}) — {status_icon} | Archivos: {verif.get('total_monitored')} | Modificados: {mod_count} | Eliminados: {del_count}"
            )
            self.after(0, lambda: self._render_results(verif))

        def _worker():
            try:
                if duration > 0:
                    targets = [target] if os.path.exists(target) else [baseline_file]
                    res = watch_integrity_timeline(
                        targets=targets,
                        duration=duration,
                        poll_interval=1.0,
                        progress_callback=_on_progress,
                        stop_check=self.stop_requested,
                    )
                else:
                    if not os.path.isfile(baseline_file):
                        raise FileNotFoundError(f"No existe el archivo de línea base '{baseline_file}'. Cree uno primero.")
                    with open(baseline_file, "r", encoding="utf-8") as f:
                        baseline = json.load(f)
                    res = verify_integrity(baseline)

                self.latest_results = res
                if self.stop_requested.is_set():
                    self.log("Verificación de integridad detenida por el usuario.")
                else:
                    self.log("Auditoría de integridad finalizada.")
                self.after(0, lambda: self._render_results(res))
                self._update_summary(res, baseline_file)
            except Exception as e:
                self.log(f"[ERROR] Error durante auditoría de integridad: {e}")
            finally:
                self.is_running = False
                self.after(0, lambda: self.btn_check.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))
                if self.stop_requested.is_set():
                    self.banner_var.set("⏹ Centinela de integridad detenido por el operador.")
                else:
                    self.banner_var.set("✔ COMPLETADO — Auditoría de integridad finalizada.")

        self.execute_async(_worker, target_duration=duration)

    def stop_analysis(self) -> None:
        super().stop_analysis()
        self.btn_check.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.banner_var.set("⏹ Centinela de integridad detenido por el operador.")

    def _render_results(self, res: Dict[str, Any]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not res:
            return

        query = self.entry_filter.get().strip().lower()

        for m in res.get("modified", []):
            p = m["path"]
            h = m["current_sha256"]
            if query and query not in p.lower() and query not in h.lower() and query not in "modificado":
                continue
            self.tree.insert(
                "", "end",
                values=(p, "⚠️ MODIFICADO (ALTERADO)", h, f"{m['current_size']} B", m["current_mtime"]),
                tags=("status_modified",)
            )

        for d in res.get("deleted", []):
            if query and query not in d.lower() and query not in "eliminado":
                continue
            self.tree.insert(
                "", "end",
                values=(d, "❌ ELIMINADO", "-", "-", "-"),
                tags=("status_deleted",)
            )

        if not res.get("tampered"):
            if not query or query in "integro" or query in "sha-256":
                self.tree.insert(
                    "", "end",
                    values=("Todos los archivos verificados", "✔ ÍNTEGRO (100% COINCIDENTE)", "SHA-256 verificado", "-", "-"),
                    tags=("status_intact",)
                )

    def _update_summary(self, res: Dict[str, Any], baseline_file: str) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INFORME FORENSE DE INTEGRIDAD CRIPTOGRÁFICA — INTEGRITYGUARD",
                "=========================================================================",
                f" Base de Datos Empleada:  {baseline_file}",
                f" Fecha de Línea Base:     {res.get('baseline_created')}",
                f" Total Archivos Auditados: {res.get('total_monitored')}",
                f" Archivos Intactos:       {res.get('intact_count')}",
                f" Archivos Manipulados:    {len(res.get('modified', []))} (!)",
                f" Archivos Desaparecidos:  {len(res.get('deleted', []))}",
                "",
                "--- DICTAMEN DE SEGURIDAD ---",
            ]
            if res.get("tampered"):
                lines.append("  [!] ALERTA CRÍTICA: Se han detectado discrepancias en el sistema.")
                for m in res.get("modified", []):
                    lines.append(f"  • MODIFICADO: {m['path']}")
                    lines.append(f"    Hash Esperado: {m['original_sha256']}")
                    lines.append(f"    Hash Real:     {m['current_sha256']}")
            else:
                lines.append("  ✔ VERIFICACIÓN EXITOSA: La integridad del sistema está garantizada.")

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
