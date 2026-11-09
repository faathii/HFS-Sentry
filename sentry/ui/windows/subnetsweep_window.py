"""Independent Desktop Window for SubnetSweep."""

import socket
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional

from sentry.tools.subnetsweep import sweep_subnet, sweep_subnet_timeline
from sentry.ui.base_window import BaseToolWindow
from sentry.ui.theme import COLORS, FONTS


class SubnetSweepWindow(BaseToolWindow):
    """SubnetSweep Independent GUI Application with Time-Window Intrusion Monitoring."""

    tool_id = "subnetsweep"
    tool_title = "SubnetSweep — Local Network Asset Discovery & OUI Resolver"
    tool_category = "Infrastructure & Asset Discovery"
    tool_version = "1.1.0"
    icon_filename = "subnetsweep.png"

    def build_controls(self, parent: ttk.Frame) -> None:
        """Construct subnet entry, duration controls, concurrency and sweep action buttons."""
        self.stop_requested = False
        self.is_running = False
        self.all_hosts: List[Dict[str, Any]] = []

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

        ttk.Label(row1, text="Subred CIDR:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.entry_cidr = ttk.Entry(row1, width=18)
        self.entry_cidr.insert(0, default_cidr)
        self.entry_cidr.pack(side="left", padx=(0, 12))

        ttk.Label(row1, text="Ventana:", style="Card.TLabel").pack(side="left", padx=(0, 6))
        self.combo_duration = ttk.Combobox(
            row1,
            values=[
                "⚡ Instantáneo (1 barrido)",
                "⏱️ Ventana 30s (Detección de Intrusos)",
                "⏱️ Ventana 60s",
                "🔄 Monitoreo Continuo",
            ],
            state="readonly",
            width=24,
        )
        self.combo_duration.current(0)
        self.combo_duration.pack(side="left", padx=(0, 12))

        self.var_icmp = tk.BooleanVar(value=True)
        self.chk_icmp = ttk.Checkbutton(row1, text="Ping ICMP", variable=self.var_icmp)
        self.chk_icmp.pack(side="left", padx=(0, 12))

        self.btn_run = ttk.Button(row1, text="▶ Iniciar Barrido", style="Primary.TButton", command=self.start_analysis)
        self.btn_run.pack(side="right", padx=4)

        self.btn_stop = ttk.Button(row1, text="⏹ Detener", command=self.stop_analysis, state="disabled")
        self.btn_stop.pack(side="right", padx=4)

        # Progress banner
        self.banner_var = tk.StringVar(value="Listo para escanear subred local.")
        self.lbl_banner = ttk.Label(parent, textvariable=self.banner_var, font=FONTS["code_sm"], foreground=COLORS["accent_cyan"])
        self.lbl_banner.pack(anchor="w", padx=4, pady=(0, 4))

    def build_results_table(self, parent: ttk.Frame) -> None:
        """Create Treeview table for discovered network devices with temporal tracking."""
        columns = ("ip", "mac", "vendor", "hostname", "status", "dur", "first_seen", "port")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="DIRECCIÓN IP")
        self.tree.heading("mac", text="DIRECCIÓN MAC (FÍSICA)")
        self.tree.heading("vendor", text="FABRICANTE / HARDWARE (OUI)")
        self.tree.heading("hostname", text="NOMBRE DE EQUIPO")
        self.tree.heading("status", text="ESTADO")
        self.tree.heading("dur", text="DURACIÓN")
        self.tree.heading("first_seen", text="INICIO")
        self.tree.heading("port", text="PUERTO RESP.")

        self.tree.column("ip", width=130, anchor="center")
        self.tree.column("mac", width=150, anchor="center")
        self.tree.column("vendor", width=220, anchor="w")
        self.tree.column("hostname", width=160, anchor="w")
        self.tree.column("status", width=100, anchor="center")
        self.tree.column("dur", width=70, anchor="center")
        self.tree.column("first_seen", width=75, anchor="center")
        self.tree.column("port", width=95, anchor="center")

        self.tree.tag_configure("host_ok", foreground=COLORS["accent_green"])
        self.tree.tag_configure("host_new", foreground=COLORS["accent_cyan"])
        self.tree.tag_configure("host_inactive", foreground="#64748b")

        scroll_y = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

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

        cidr = self.entry_cidr.get().strip()
        if not cidr:
            messagebox.showerror("Dato Requerido", "Por favor ingrese una subred en notación CIDR.")
            return

        duration = self._get_selected_duration()
        use_icmp = self.var_icmp.get()

        self.is_running = True
        self.stop_requested = False
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.clear_results()
        mode_str = f"Ventana {int(duration)}s" if duration < 100000 and duration > 0 else ("Monitoreo Continuo" if duration > 0 else "Instantáneo")
        self.log(f"Iniciando barrido de red sobre '{cidr}' — Modo: {mode_str}...")

        def _on_progress(cumulative_hosts: List[Dict[str, Any]], remaining: float):
            self.all_hosts = cumulative_hosts
            active_cnt = sum(1 for h in cumulative_hosts if h.get("status") == "ACTIVO")
            new_cnt = sum(1 for h in cumulative_hosts if h.get("is_new"))

            rem_text = f"{int(remaining)}s restantes" if duration < 100000 and duration > 0 else "Modo Continuo"
            self.banner_var.set(
                f"● OBSERVANDO RED ({rem_text}) — Hosts Vistos: {len(cumulative_hosts)} | Activos: {active_cnt} | Nuevos Detectados: {new_cnt}"
            )
            self.after(0, self._render_hosts)

        def _worker():
            start_t = time.time()
            try:
                if duration > 0:
                    hosts = sweep_subnet_timeline(
                        cidr=cidr,
                        duration=duration,
                        interval=4.0,
                        workers=35,
                        use_icmp=use_icmp,
                        progress_callback=_on_progress,
                        stop_check=lambda: self.stop_requested,
                    )
                else:
                    hosts = sweep_subnet(cidr=cidr, workers=35, use_icmp=use_icmp)
                    for h in hosts:
                        h["status"] = "ACTIVO"
                        h["duration_sec"] = round(time.time() - start_t, 1)
                        h["first_seen"] = time.strftime("%H:%M:%S")

                self.all_hosts = hosts
                elapsed = round(time.time() - start_t, 2)
                self.latest_results = {
                    "tool": "SubnetSweep",
                    "subnet": cidr,
                    "duration_seconds": duration,
                    "active_hosts_count": len(hosts),
                    "hosts": hosts,
                }
                self.log(f"Barrido completado en {elapsed}s. {len(hosts)} dispositivos localizados.")
                self.after(0, self._render_hosts)
                self._update_summary(self.latest_results, elapsed)
            except Exception as e:
                self.log(f"[ERROR] Error durante el barrido de subred: {e}")
            finally:
                self.is_running = False
                self.after(0, lambda: self.btn_run.configure(state="normal"))
                self.after(0, lambda: self.btn_stop.configure(state="disabled"))
                self.banner_var.set(f"✔ COMPLETADO — {len(self.all_hosts)} hosts descubiertos en la subred.")

        self.execute_async(_worker)

    def stop_analysis(self) -> None:
        if self.is_running:
            self.stop_requested = True
            self.log("[*] Solicitud de parada de barrido enviada...")
            self.btn_stop.configure(state="disabled")

    def _render_hosts(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        for h in getattr(self, "all_hosts", []):
            status = h.get("status", "ACTIVO")
            is_new = h.get("is_new", False)

            if is_new:
                tag = "host_new"
                status_disp = "✦ NUEVO (+)"
            elif status == "INACTIVO":
                tag = "host_inactive"
                status_disp = "○ INACTIVO"
            else:
                tag = "host_ok"
                status_disp = "● ACTIVO"

            dur_str = f"{h.get('duration_sec', 0.0)}s"
            first_seen_str = h.get("first_seen", "-")

            self.tree.insert(
                "", "end",
                values=(
                    h["ip"],
                    h.get("mac", "-"),
                    h.get("vendor", "-"),
                    h.get("hostname", "-"),
                    status_disp,
                    dur_str,
                    first_seen_str,
                    h.get("responsive_port") or "-",
                ),
                tags=(tag,)
            )

    def _update_summary(self, data: dict, elapsed: float) -> None:
        def _render():
            self.summary_text.delete("1.0", "end")
            hosts = data.get("hosts", [])
            lines = [
                "=========================================================================",
                " INFORME DE INVENTARIO DE SUBRED LOCAL — SUBNETSWEEP",
                "=========================================================================",
                f" Subred Objetiva:         {data.get('subnet')}",
                f" Tiempo de Observación:   {elapsed} segundos",
                f" Dispositivos Descubiertos: {len(hosts)} activos",
                "",
                "--- DISTRIBUCIÓN POR FABRICANTE (IEEE OUI) ---",
            ]

            vendor_count = {}
            for h in hosts:
                v = h.get("vendor", "Desconocido")
                vendor_count[v] = vendor_count.get(v, 0) + 1

            for v, count in sorted(vendor_count.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  • {v:<35} : {count} dispositivo(s)")

            lines.append("\n--- MAPEO DETALLADO DE ACTIVOS ---")
            for h in hosts:
                lines.append(f"  • {h['ip']:<15} | MAC: {h.get('mac', '-'):<17} | Host: {h.get('hostname', '-')} | Fabricante: {h.get('vendor', '-')}")

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
