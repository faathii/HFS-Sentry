"""Independent Desktop Window for CertSentry."""

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from sentry.tools.certsentry import inspect_certificate
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class CertSentryWindow(BaseToolWindow):
    """CertSentry Independent GUI Application."""

    tool_id = "certsentry"
    tool_title = "CertSentry — SSL/TLS & Cryptographic Auditor"
    tool_category = "Cryptography & PKI"
    tool_version = "1.0.0"
    icon_filename = "certsentry.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct domain input, port and action buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        ttk.Label(row1, text="Dominio / Host TLS:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_host = ttk.Entry(row1, width=32)
        self.entry_host.insert(0, "google.com")
        self.entry_host.pack(side="left", padx=(0, 16))

        ttk.Label(row1, text="Puerto:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_port = ttk.Spinbox(row1, from_=1, to=65535, width=6)
        self.spin_port.set("443")
        self.spin_port.pack(side="left", padx=(0, 16))

        ttk.Label(row1, text="Timeout (s):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_timeout = ttk.Spinbox(row1, from_=1, to=30, width=5)
        self.spin_timeout.set("3.0")
        self.spin_timeout.pack(side="left", padx=(0, 16))

        self.btn_run = ttk.Button(row1, text="▶ Inspeccionar Certificado", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for cryptographic details."""
        columns = ("prop", "val", "status")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("prop", text="PROPIEDAD CRIPTOGRÁFICA")
        self.tree.heading("val", text="VALOR OBTENIDO")
        self.tree.heading("status", text="EVALUACIÓN DE SEGURIDAD")

        self.tree.column("prop", width=220, anchor="w")
        self.tree.column("val", width=420, anchor="w")
        self.tree.column("status", width=220, anchor="center")

        self.tree.tag_configure("status_ok", foreground=COLORS["accent_green"])
        self.tree.tag_configure("status_warn", foreground=COLORS["accent_yellow"])
        self.tree.tag_configure("status_crit", foreground=COLORS["accent_red"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def start_analysis(self) -> None:
        host = self.entry_host.get().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if not host:
            messagebox.showerror("Dato Requerido", "Por favor ingrese un dominio o hostname TLS.")
            return

        port = int(self.spin_port.get())
        timeout = float(self.spin_timeout.get())

        self.clear_results()
        self.log(f"Iniciando inspección TLS sobre {host}:{port}...")

        def _worker():
            try:
                data = inspect_certificate(host, port=port, timeout=timeout)
                self.log(f"Certificado X.509 recibido de {host}. Estado: [{data['status']}]")

                # Insert into table
                days = data["days_remaining"]
                stat_tag = "status_ok" if data["status"] == "HEALTHY" else ("status_warn" if data["status"] in ("NOTICE", "WARNING") else "status_crit")

                self.after(0, lambda: self._populate_tree(data, stat_tag))
                self.latest_results = data
                self._update_summary(data)
            except Exception as e:
                self.log(f"[ERROR] Falló la negociación TLS: {e}")

        self.execute_async(_worker)

    def _populate_tree(self, d: dict, stat_tag: str) -> None:
        rows = [
            ("Salud de Caducidad", f"{d['days_remaining']} días restantes ({d['valid_until']})", stat_tag, d['status']),
            ("Sujeto (CN)", d["subject_cn"], "status_ok", "Válido"),
            ("Entidad Emisora (CA)", d["issuer_org"], "status_ok", "Confianza Pública"),
            ("Protocolo Negociado", d["negotiated_protocol"], "status_ok", "Moderno"),
            ("Algoritmo de Cifrado", f"{d['negotiated_cipher']} ({d['cipher_bits']} bits)", "status_ok", "Fuerte"),
            (
                "Soporte TLS 1.0 / 1.1",
                "Acepta protocolos obsoletos" if d["legacy_tls_detected"] else "Rechaza protocolos inseguros",
                "status_crit" if d["legacy_tls_detected"] else "status_ok",
                "VULNERABLE" if d["legacy_tls_detected"] else "SEGURO"
            ),
            ("Número de Serie", d["serial_number"], "status_ok", "Identificador"),
            ("SANs (Dominios)", ", ".join(d["sans"][:5]) + ("..." if d["sans_count"] > 5 else ""), "status_ok", f"{d['sans_count']} dominios"),
        ]
        for prop, val, tag, status_txt in rows:
            self.tree.insert("", "end", values=(prop, val, status_txt), tags=(tag,))

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INFORME DE AUDITORÍA CRIPTOGRÁFICA — CERTSENTRY",
                "=========================================================================",
                f" Objetivo:                {data['host']}:{data['port']}",
                f" Estado General:          {data['status']} ({data['days_remaining']} días de validez restante)",
                f" Válido Hasta:            {data['valid_until']}",
                f" Entidad Certificadora:   {data['issuer_org']}",
                f" Nombre Común (CN):       {data['subject_cn']}",
                "",
                "--- PROTOCOLOS Y SUITE CRIPTOGRÁFICA ---",
                f" Protocolo TLS Negociado: {data['negotiated_protocol']}",
                f" Algoritmo Cifrado:       {data['negotiated_cipher']} ({data['cipher_bits']} bits)",
                f" Exposición TLS 1.0/1.1:  {'¡VULNERABLE! Servidor acepta protocolos obsoletos' if data['legacy_tls_detected'] else 'HARDENED / ÓPTIMO (rechaza cifrados antiguos)'}",
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
