"""Independent Desktop Window for IntegrityGuard (FIM)."""

import os
import platform
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from sentry.tools.integrityguard import (
    DEFAULT_TARGET_PATHS,
    collect_file_metadata,
    generate_baseline,
    verify_integrity,
)
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class IntegrityGuardWindow(BaseToolWindow):
    """IntegrityGuard Independent GUI Application."""

    tool_id = "integrityguard"
    tool_title = "IntegrityGuard — Host File Integrity Monitor (FIM)"
    tool_category = "HIDS & Forensics"
    tool_version = "1.0.0"
    icon_filename = "integrityguard.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct baseline file picker, target manager and check buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        ttk.Label(row1, text="Base de Datos Baseline (JSON):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_baseline = ttk.Entry(row1, width=32)
        self.entry_baseline.insert(0, "sentry_baseline.json")
        self.entry_baseline.pack(side="left", padx=(0, 16))

        btn_browse_base = ttk.Button(row1, text="📁 Examinar...", command=self._browse_baseline)
        btn_browse_base.pack(side="left", padx=(0, 16))

        # Action Buttons
        self.btn_check = ttk.Button(row1, text="🛡️ Verificar Integridad", style="Primary.TButton", command=self.start_analysis)
        self.btn_check.pack(side="right", padx=4)

        self.btn_init = ttk.Button(row1, text="➕ Crear Línea Base (SHA-256)", command=self._create_baseline)
        self.btn_init.pack(side="right", padx=4)

        row2 = ttk.Frame(parent, style="Card.TFrame")
        row2.pack(fill="x", pady=(8, 2))

        ttk.Label(row2, text="Archivos / Directorios a Vigilar:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_target = ttk.Entry(row2, width=45)
        # Default target
        sys_os = platform.system()
        def_target = DEFAULT_TARGET_PATHS.get(sys_os, [DEFAULT_TARGET_PATHS["Linux"][0]])[0]
        self.entry_target.insert(0, def_target)
        self.entry_target.pack(side="left", padx=(0, 8))

        btn_add_file = ttk.Button(row2, text="+ Archivo", command=self._add_file_target)
        btn_add_file.pack(side="left", padx=2)

        btn_add_dir = ttk.Button(row2, text="+ Carpeta", command=self._add_dir_target)
        btn_add_dir.pack(side="left", padx=2)

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
            title="Seleccionar Base de Datos de Integridad (JSON)",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if path:
            self.entry_baseline.delete(0, "end")
            self.entry_baseline.insert(0, path)

    def _add_file_target(self) -> None:
        path = filedialog.askopenfilename(title="Seleccionar Archivo para Línea Base")
        if path:
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, path)

    def _add_dir_target(self) -> None:
        path = filedialog.askdirectory(title="Seleccionar Carpeta para Línea Base")
        if path:
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, path)

    def _create_baseline(self) -> None:
        target = self.entry_target.get().strip()
        baseline_file = self.entry_baseline.get().strip()

        if not target:
            messagebox.showerror("Error", "Indique un archivo o directorio para generar la línea base.")
            return

        self.clear_results()
        self.log(f"Generando firmas SHA-256 para '{target}' en '{baseline_file}'...")

        def _worker():
            try:
                data = generate_baseline([target], baseline_file)
                self.log(f"[✔] Línea base creada exitosamente: {data['total_files']} archivos firmados.")
                for path, meta in data.get("files", {}).items():
                    self.after(0, lambda p=path, m=meta: self.tree.insert(
                        "", "end", values=(p, "LÍNEA BASE", m["sha256"][:24] + "...", f"{m['size_bytes']} B", m["mtime_iso"][:19]), tags=("status_intact",)
                    ))
                messagebox.showinfo("Línea Base Lista", f"Línea base generada correctamente con {data['total_files']} archivos.")
            except Exception as e:
                self.log(f"[ERROR] No se pudo crear la línea base: {e}")

        self.execute_async(_worker)

    def start_analysis(self) -> None:
        """Verify integrity against baseline snapshot."""
        baseline_file = self.entry_baseline.get().strip()
        if not os.path.isfile(baseline_file):
            messagebox.showwarning("Línea Base Requerida", f"El archivo '{baseline_file}' no existe. Genere primero una línea base con '➕ Crear Línea Base'.")
            return

        self.clear_results()
        self.log(f"Comprobando integridad criptográfica contra '{baseline_file}'...")

        def _worker():
            try:
                results = verify_integrity(baseline_file)
                self.latest_results = results

                if not results["tampered"]:
                    self.log(f"[✔] INTEGRIDAD VERIFICADA: Los {results['total_monitored']} archivos coinciden exactamente.")
                else:
                    self.log(f"[!] ALERTA: Alteraciones detectadas ({len(results['modified'])} modificados, {len(results['deleted'])} eliminados)")

                for m in results["modified"]:
                    self.after(0, lambda mod=m: self.tree.insert(
                        "", "end", values=(mod["path"], "¡MODIFICADO!", mod["current_sha256"][:24] + "...", f"{mod['current_size']} B", mod["current_mtime"][:19]), tags=("status_modified",)
                    ))
                for d in results["deleted"]:
                    self.after(0, lambda del_p=d: self.tree.insert(
                        "", "end", values=(del_p, "¡ELIMINADO!", "-", "-", "-"), tags=("status_deleted",)
                    ))

                self._update_summary(results)
            except Exception as e:
                self.log(f"[ERROR] Falló la verificación de integridad: {e}")

        self.execute_async(_worker)

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INFORME DE INTEGRIDAD CRIPTOGRÁFICA (FIM) — INTEGRITYGUARD",
                "=========================================================================",
                f" Archivo Baseline:        {self.entry_baseline.get()}",
                f" Archivos Monitoreados:   {data.get('total_monitored', 0)}",
                f" Archivos Intactos:       {data.get('intact_count', 0)}",
                f" Discrepancias / Daños:   {'¡ALTERADO!' if data.get('tampered') else 'NINGUNO (100% INTACTO)'}",
                "",
                "--- DETALLES DE ALTERACIONES ---",
            ]
            if not data.get("tampered"):
                lines.append("  [✔] El sistema se encuentra en su estado original certificado por SHA-256.")
            else:
                for m in data.get("modified", []):
                    lines.append(f"  [MODIFICADO] {m['path']}")
                    lines.append(f"       Hash Esperado: {m['original_sha256']}")
                    lines.append(f"       Hash Actual:   {m['current_sha256']}")
                for d in data.get("deleted", []):
                    lines.append(f"  [ELIMINADO / DESAPARECIDO] {d}")

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
