"""Desktop Modal Dialog for System Quick Audit & Security Hardening Score."""

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from sentry.core.quick_audit import run_system_quick_audit
from sentry.core.report import generate_html_report
from sentry.ui.theme import COLORS, FONTS


class QuickAuditDialog(tk.Toplevel):
    """Modal dialog displaying 1-Click System Security Score & Checklist."""

    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master)
        self.title("⚡ Diagnóstico Rápido del Sistema — HFS-Sentry")
        self.geometry("780x560")
        self.minsize(700, 480)
        self.configure(bg=COLORS["bg_dark"])
        self.transient(master)
        self.grab_set()

        self.latest_data = None

        self._build_header()
        self._build_score_card()
        self._build_checklist_table()
        self._build_action_bar()

        # Run immediately on open
        self.after(100, self.start_audit)

    def _build_header(self) -> None:
        hdr = ttk.Frame(self, padding=(20, 14), style="Card.TFrame")
        hdr.pack(fill="x", padx=16, pady=(16, 8))

        ttk.Label(
            hdr,
            text="⚡ Auditoría Rápida de Salud y Endurecimiento",
            font=FONTS["title_medium"],
            foreground=COLORS["accent_cyan"],
            style="Card.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            hdr,
            text="Diagnóstico simultáneo de superficie perimetral, integridad del host y criptografía.",
            font=FONTS["caption"],
            foreground=COLORS["text_secondary"],
            style="Card.TLabel",
        ).pack(anchor="w")

    def _build_score_card(self) -> None:
        """Card showing circular-style numeric score and grade."""
        self.score_card = ttk.Frame(self, padding=16, style="Surface.TFrame")
        self.score_card.pack(fill="x", padx=16, pady=4)

        # Left: Score Number
        score_left = ttk.Frame(self.score_card, style="Surface.TFrame")
        score_left.pack(side="left", padx=10)

        self.lbl_score_num = tk.Label(
            score_left,
            text="--",
            font=("Segoe UI", 36, "bold"),
            bg=COLORS["surface"],
            fg=COLORS["accent_cyan"],
        )
        self.lbl_score_num.pack(side="left")

        tk.Label(
            score_left,
            text="/ 100",
            font=FONTS["title_small"],
            bg=COLORS["surface"],
            fg=COLORS["text_secondary"],
        ).pack(side="left", padx=(4, 16))

        # Middle: Grade & Label
        grade_box = ttk.Frame(self.score_card, style="Surface.TFrame")
        grade_box.pack(side="left", fill="y", padx=10)

        self.lbl_grade = tk.Label(
            grade_box,
            text="CALCULANDO...",
            font=FONTS["title_medium"],
            bg=COLORS["surface"],
            fg=COLORS["accent_green"],
        )
        self.lbl_grade.pack(anchor="w")

        self.lbl_grade_desc = tk.Label(
            grade_box,
            text="Evaluando parámetros de seguridad en tiempo real...",
            font=FONTS["caption"],
            bg=COLORS["surface"],
            fg=COLORS["text_secondary"],
        )
        self.lbl_grade_desc.pack(anchor="w")

    def _build_checklist_table(self) -> None:
        """Table showing individual audit items."""
        box = ttk.Frame(self, padding=12, style="Card.TFrame")
        box.pack(fill="both", expand=True, padx=16, pady=8)

        cols = ("status", "check", "score", "details")
        self.tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")

        self.tree.heading("status", text="ESTADO")
        self.tree.heading("check", text="VERIFICACIÓN PERIMETRAL")
        self.tree.heading("score", text="PUNTOS")
        self.tree.heading("details", text="DETALLES TÉCNICOS")

        self.tree.column("status", width=90, anchor="center")
        self.tree.column("check", width=220, anchor="w")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("details", width=340, anchor="w")

        self.tree.tag_configure("pass", foreground=COLORS["accent_green"])
        self.tree.tag_configure("warn", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("fail", foreground=COLORS["accent_red"])

        scroll = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_action_bar(self) -> None:
        bar = ttk.Frame(self, padding=(16, 12), style="Surface.TFrame")
        bar.pack(fill="x", side="bottom")

        btn_html = ttk.Button(bar, text="📄 Exportar Informe HTML", command=self.export_html)
        btn_html.pack(side="left", padx=4)

        btn_rerun = ttk.Button(bar, text="🔄 Re-ejecutar Diagnóstico", command=self.start_audit)
        btn_rerun.pack(side="left", padx=4)

        btn_close = ttk.Button(bar, text="Cerrar", command=self.destroy)
        btn_close.pack(side="right", padx=4)

    def start_audit(self) -> None:
        """Run audit asynchronously."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.lbl_score_num.config(text="--", fg=COLORS["accent_cyan"])
        self.lbl_grade.config(text="ANALIZANDO...", fg=COLORS["accent_cyan"])

        def _worker():
            data = run_system_quick_audit()
            self.latest_data = data
            self.after(0, lambda: self._display_results(data))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_results(self, data: dict) -> None:
        score = data["security_score"]
        grade = data["grade"]
        grade_label = data["grade_label"]

        score_color = COLORS["accent_green"] if score >= 85 else (COLORS["accent_yellow"] if score >= 70 else COLORS["accent_red"])

        self.lbl_score_num.config(text=str(score), fg=score_color)
        self.lbl_grade.config(text=f"GRADO [{grade}]: {grade_label}", fg=score_color)
        self.lbl_grade_desc.config(text=f"Host: {data['hostname']}  |  IP: {data['local_ip']}  |  Tiempo: {data['elapsed_seconds']}s")

        for c in data.get("checks", []):
            st = c["status"]
            tag = "pass" if st == "PASS" else ("warn" if st in ("WARN", "NOTICE") else "fail")
            st_text = "[PASÓ]" if st == "PASS" else ("[AVISO]" if st == "WARN" else "[FALLÓ]")
            self.tree.insert("", "end", values=(st_text, c["name"], f"{c['score']}/25", c["details"]), tags=(tag,))

    def export_html(self) -> None:
        if not self.latest_data:
            messagebox.showinfo("Sin Datos", "Ejecute el diagnóstico primero.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Informes HTML", "*.html"), ("Todos los archivos", "*.*")],
            title="Exportar Informe de Diagnóstico Rápido",
            initialfile="hfs_sentry_quick_audit.html",
        )
        if path:
            html = generate_html_report(self.latest_data, title="Auditoría Rápida de Salud — HFS-Sentry")
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo("Guardado", f"Informe HTML guardado en:\n{path}")

