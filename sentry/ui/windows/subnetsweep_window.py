"""Independent Desktop Window for SubnetSweep."""

import socket
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from sentry.tools.subnetsweep import sweep_subnet
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class SubnetSweepWindow(BaseToolWindow):
    """SubnetSweep Independent GUI Application."""

    tool_id = "subnetsweep"
    tool_title = "SubnetSweep — Local Network Asset Discovery & OUI Resolver"
    tool_category = "Infrastructure & Asset Discovery"
    tool_version = "1.0.0"
    icon_filename = "subnetsweep.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct subnet entry, concurrency controls and sweep action buttons."""
        row1 = ttk.Frame(parent, style="Card.TFrame")
        row1.pack(fill="x", pady=2)

        # Detect local IP
        default_cidr = "192.168.1.0/24"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            default_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

        ttk.Label(row1, text="Subred CIDR (ej. 192.168.1.0/24):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_cidr = ttk.Entry(row1, width=28)
        self.entry_cidr.insert(0, default_cidr)
        self.entry_cidr.pack(side="left", padx=(0, 16))

        ttk.Label(row1, text="Hilos Concurrencia:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.spin_threads = ttk.Spinbox(row1, from_=5, to=100, width=5)
        self.spin_threads.set("40")
        self.spin_threads.pack(side="left", padx=(0, 16))

        self.var_icmp = tk.BooleanVar(value=True)
        self.chk_icmp = ttk.Checkbutton(row1, text="Habilitar Ping ICMP", variable=self.var_icmp)
        self.chk_icmp.pack(side="left", padx=(0, 20))

        self.btn_run = ttk.Button(row1, text="▶ Iniciar Barrido de Red", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

        self.btn_stop = ttk.Button(row1, text="⏹ Detener", style="Danger.TButton", command=self.stop_analysis)
        self.btn_stop.pack(side="right", padx=4)

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for discovered network devices."""
        columns = ("ip", "mac", "vendor", "hostname", "port")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="DIRECCIÓN IP")
        self.tree.heading("mac", text="DIRECCIÓN MAC (FÍSICA)")
        self.tree.heading("vendor", text="FABRICANTE / HARDWARE (OUI)")
        self.tree.heading("hostname", text="NOMBRE DE EQUIPO")
        self.tree.heading("port", text="PUERTO RESPONSIVO")

        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("mac", width=160, anchor="center")
        self.tree.column("vendor", width=260, anchor="w")
        self.tree.column("hostname", width=220, anchor="w")
        self.tree.column("port", width=120, anchor="center")

        self.tree.tag_configure("host_ok", foreground=COLORS["accent_green"])

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def start_analysis(self) -> None:
        cidr = self.entry_cidr.get().strip()
        if not cidr:
            messagebox.showerror("Dato Requerido", "Por favor ingrese una subred en notación CIDR.")
            return

        workers = int(self.spin_threads.get())
        use_icmp = self.var_icmp.get()

        self.clear_results()
        self.log(f"Iniciando barrido concurrente sobre subred '{cidr}' ({workers} hilos)...")

        def _worker():
            start_t = time.time()
            try:
                hosts = sweep_subnet(cidr, workers=workers, use_icmp=use_icmp)
                elapsed = round(time.time() - start_t, 2)
                self.log(f"Barrido completado en {elapsed}s. Dispositivos activos encontrados: {len(hosts)}")

                for h in hosts:
                    port_str = f"TCP {h['responsive_port']}" if h.get("responsive_port") else "ICMP"
                    self.after(0, lambda dev=h, p=port_str: self.tree.insert(
                        "", "end", values=(dev["ip"], dev["mac"], dev["vendor"], dev["hostname"], p), tags=("host_ok",)
                    ))
                    self.log(f"[ACTIVO] {h['ip']} | MAC: {h['mac']} | Fabricante: {h['vendor']}")

                self.latest_results = {
                    "tool": "SubnetSweep",
                    "subnet": cidr,
                    "elapsed_seconds": elapsed,
                    "active_hosts": len(hosts),
                    "hosts": hosts,
                }
                self._update_summary(self.latest_results)
            except Exception as e:
                self.log(f"[ERROR] Falló el barrido de red: {e}")

        self.execute_async(_worker)

    def _update_summary(self, data: dict) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            lines = [
                "=========================================================================",
                " INVENTARIO DE INFRAESTRUCTURA DE RED — SUBNETSWEEP",
                "=========================================================================",
                f" Subred Explorada:        {data['subnet']}",
                f" Dispositivos Detectados: {data['active_hosts']} activos",
                f" Tiempo de Sondeo:        {data['elapsed_seconds']} segundos",
                "",
                "--- DISPOSITIVOS Y HARDWARE IDENTIFICADO ---",
            ]
            if not data["hosts"]:
                lines.append("  Ningún host respondió en la subred indicada.")
            else:
                for h in data["hosts"]:
                    lines.append(f"  • {h['ip']} -> MAC: {h['mac']} | {h['vendor']} ({h['hostname']})")

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
