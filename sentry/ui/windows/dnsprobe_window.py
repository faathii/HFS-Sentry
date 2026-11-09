"""Independent Desktop Window for DnsProbe."""

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from sentry.tools.dnsprobe import run_dnsprobe
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class DnsProbeWindow(BaseToolWindow):
    """DnsProbe Independent GUI Application."""

    tool_id = "dnsprobe"
    tool_title = "DnsProbe — DNS Reconnaissance & Email Defense"
    tool_category = "DNS & Email Security"
    tool_version = "1.0.0"
    icon_filename = "dnsprobe.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct domain input, timeout and responsive probe action buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        ttk.Label(row1, text="Dominio Objetivo:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_domain = ttk.Entry(row1, width=28)
        self.entry_domain.insert(0, "google.com")
        self.entry_domain.pack(side="left", fill="x", expand=True, padx=(0, 14))

        ttk.Label(row1, text="Timeout (s):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_timeout = ttk.Spinbox(row1, from_=1, to=15, width=5)
        self.spin_timeout.set("3.0")
        self.spin_timeout.pack(side="left", padx=(0, 16))

        self.btn_stop = ttk.Button(row1, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=(4, 0))

        self.btn_run = ttk.Button(row1, text="▶ Auditar DNS & Correo", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for DNS records and email security posture."""
        columns = ("type", "value", "security")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("type", text="TIPO DE REGISTRO")
        self.tree.heading("value", text="VALOR / DESTINO")
        self.tree.heading("security", text="ESTADO DE SEGURIDAD")

        self.tree.column("type", width=140, anchor="center")
        self.tree.column("value", width=460, anchor="w")
        self.tree.column("security", width=220, anchor="center")

        self.tree.tag_configure("sec_pass", foreground=COLORS["accent_green"])
        self.tree.tag_configure("sec_warn", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("sec_fail", foreground=COLORS["accent_red"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def apply_prefill(self, value: str) -> None:
        """Prefill target domain from cross-tool pivot."""
        clean = value.split(":")[0].replace("https://", "").replace("http://", "").split("/")[0]
        self.entry_domain.delete(0, "end")
        self.entry_domain.insert(0, clean)
        self.entry_domain.focus_set()

    def start_analysis(self) -> None:
        domain = self.entry_domain.get().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            messagebox.showerror("Dato Requerido", "Por favor ingrese un dominio.")
            return

        timeout = float(self.spin_timeout.get())
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.clear_results()
        self.log(f"Iniciando sondeo DNS y verificación SPF/DMARC sobre '{domain}'...")

        def _worker():
            try:
                report = run_dnsprobe(domain, timeout=timeout)
                self.latest_results = report

                dnssec_str = "Habilitado (Firmado)" if report["dnssec_validated"] else "No Validado"
                dnssec_tag = "sec_pass" if report["dnssec_validated"] else "sec_warn"
                self.after(0, lambda: self.tree.insert("", "end", values=("DNSSEC", dnssec_str, dnssec_str), tags=(dnssec_tag,)))

                # SPF
                spf = report["email_security"]["spf"]
                spf_tag = "sec_pass" if spf["status"] == "PASS" else ("sec_warn" if spf["status"] == "WARN" else "sec_fail")
                self.after(0, lambda: self.tree.insert("", "end", values=("SPF", spf.get("raw") or "Ausente", spf["notes"]), tags=(spf_tag,)))

                # DMARC
                dmarc = report["email_security"]["dmarc"]
                dmarc_tag = "sec_pass" if dmarc["status"] == "PASS" else ("sec_warn" if dmarc["status"] == "WARN" else "sec_fail")
                self.after(0, lambda: self.tree.insert("", "end", values=("DMARC", dmarc.get("raw") or "Ausente", dmarc["notes"]), tags=(dmarc_tag,)))

                # Records
                for rtype, vals in report["records"].items():
                    for v in vals:
                        self.after(0, lambda t=rtype, val=v: self.tree.insert("", "end", values=(t, val, "OK"), tags=("sec_pass",)))

                self.log(f"Auditoría DNS completada. Postura de correo: [{report['email_security']['overall_email_rating']}]")
                self._update_summary(report)
            except Exception as e:
                self.log(f"[ERROR] Falló DnsProbe: {e}")

            finally:
                self.after(0, lambda: self.btn_run.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))

        self.execute_async(_worker)

    def stop_analysis(self) -> None:
        super().stop_analysis()
        self.btn_run.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            em = data["email_security"]
            lines = [
                "=========================================================================",
                " INFORME DE SEGURIDAD DNS Y SUPLANTACIÓN — DNSPROBE",
                "=========================================================================",
                f" Dominio:                 {data['domain']}",
                f" Postura Anti-Spoofing:   {em['overall_email_rating']}",
                f" DNSSEC (DoH Validated):  {'Sí' if data['dnssec_validated'] else 'No'}",
                "",
                "--- ESTADO DE DEFENSAS SPF Y DMARC ---",
                f" SPF:   {em['spf']['status']} -> {em['spf']['notes']}",
                f" DMARC: {em['dmarc']['status']} -> {em['dmarc']['notes']}",
                "\n=========================================================================\n"
            ]
            self.summary_text.insert("end", "\n".join(lines))
        self.after(0, _render)

    def clear_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.console_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")
        self.latest_results = None
        self.set_status("Listo.")

