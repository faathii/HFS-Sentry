"""HFS-Sentry Desktop Suite Hub Application.

Modular desktop launcher designed like Adobe Creative Cloud or Microsoft Suite.
Opens individual, independent tool windows on demand.
Zero external dependencies (Python 3 standard library + Tkinter).
"""

import os
import platform
import socket
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, Optional
import webbrowser

from sentry import __version__
from sentry.ui.theme import COLORS, FONTS, apply_suite_theme, load_icon
from sentry.ui.windows import TOOL_WINDOW_MAP


class SentrySuiteApp(tk.Tk):
    """Main desktop launcher window for HFS-Sentry Cybersecurity Suite."""

    def __init__(self) -> None:
        super().__init__()
        self.title(f"HFS-Sentry Suite Hub v{__version__} — Cybersecurity Diagnostic Suite")
        self.geometry("1120x760")
        self.minsize(920, 620)
        self.configure(bg=COLORS["bg_dark"])

        apply_suite_theme(self)

        # Set main window icon
        try:
            icon_path = os.path.join("assets", "logos", "hfs_sentry.png")
            self.hub_icon = load_icon(icon_path, size=(32, 32))
            if self.hub_icon:
                self.iconphoto(False, self.hub_icon)
        except Exception:
            self.hub_icon = None

        # Track active child tool windows: {tool_id: [window_instances]}
        self.active_tool_windows: Dict[str, list] = {}

        self._build_menu()
        self._build_header()
        self._build_tools_grid()
        self._build_footer()

    def _build_menu(self) -> None:
        """Create global suite menu bar."""
        menubar = tk.Menu(self, bg=COLORS["bg_card"], fg=COLORS["text_primary"])

        # Archivo
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        file_menu.add_command(label="Comprobar Conectividad de Red", command=self._check_network_status)
        file_menu.add_separator()
        file_menu.add_command(label="Salir de la Suite\tCtrl+Q", command=self.quit)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        # Herramientas
        tools_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        tools_menu.add_command(label="NetSentry — Escáner de Puertos & OWASP", command=lambda: self.launch_tool("netsentry"))
        tools_menu.add_command(label="LogSentinel — Analizador Forense de Logs & IDS", command=lambda: self.launch_tool("logsentinel"))
        tools_menu.add_command(label="CertSentry — Auditor SSL/TLS & Criptografía", command=lambda: self.launch_tool("certsentry"))
        tools_menu.add_command(label="SubnetSweep — Descubridor de Activos de Red", command=lambda: self.launch_tool("subnetsweep"))
        tools_menu.add_command(label="IntegrityGuard — Monitor de Integridad (FIM)", command=lambda: self.launch_tool("integrityguard"))
        tools_menu.add_command(label="DnsProbe — Reconocimiento DNS & Anti-Spoofing", command=lambda: self.launch_tool("dnsprobe"))
        tools_menu.add_command(label="TrafficSentry — Auditor de Sockets & Conexiones Activas", command=lambda: self.launch_tool("trafficsentry"))
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        # Ajustes
        settings_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        settings_menu.add_command(label="Preferencias de la Suite...", command=self._show_suite_settings)
        menubar.add_cascade(label="Ajustes", menu=settings_menu)

        # Ayuda
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        help_menu.add_command(label="Repositorio de GitHub (Código Abierto)", command=self._open_github)
        help_menu.add_command(label="Guía de Contribución y Nuevas Herramientas", command=self._open_contributing)
        help_menu.add_separator()
        help_menu.add_command(label="Acerca de HFS-Sentry Suite", command=self._show_about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

        self.config(menu=menubar)
        self.bind("<Control-q>", lambda e: self.quit())

    def _build_header(self) -> None:
        """Top hero header with banner logo and telemetry metrics."""
        hero = ttk.Frame(self, padding=(24, 16), style="Card.TFrame")
        hero.pack(fill="x", padx=16, pady=(14, 10))

        # Main horizontal logo
        logo_path = os.path.join("assets", "logos", "hfs_sentry_main.png")
        self.main_logo_photo = load_icon(logo_path, size=(280, 127))
        if self.main_logo_photo:
            logo_lbl = ttk.Label(hero, image=self.main_logo_photo, style="Card.TLabel")
            logo_lbl.pack(side="left", padx=(0, 20))
        else:
            title_block = ttk.Frame(hero, style="Card.TFrame")
            title_block.pack(side="left")
            ttk.Label(title_block, text="HFS-Sentry", font=FONTS["title_large"], foreground=COLORS["accent_cyan"], style="Card.TLabel").pack(anchor="w")
            ttk.Label(title_block, text="Cybersecurity & Diagnostic Suite", font=FONTS["body"], style="CardSecondary.TLabel").pack(anchor="w")

        # Telemetry panel on the right
        telemetry_box = ttk.Frame(hero, padding=12, style="Surface.TFrame")
        telemetry_box.pack(side="right", fill="y")

        # Discover real local network info
        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        ttk.Label(telemetry_box, text="TELEMETRÍA DEL SISTEMA LOCAL", font=FONTS["title_small"], foreground=COLORS["accent_cyan"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(telemetry_box, text=f"• Hostname: {hostname}  |  IP Local: {local_ip}", font=FONTS["caption"], foreground=COLORS["text_secondary"]).pack(anchor="w")
        ttk.Label(telemetry_box, text=f"• Sistema: {os_info}  |  Python: {platform.python_version()}", font=FONTS["caption"], foreground=COLORS["text_secondary"]).pack(anchor="w")
        ttk.Label(telemetry_box, text="• Motor: 100% Nativo Local (Cero dependencias externas)", font=FONTS["caption"], foreground=COLORS["accent_green"]).pack(anchor="w", pady=(0, 8))

        btn_qa = ttk.Button(telemetry_box, text="⚡ Auditoría Rápida del Sistema", style="Primary.TButton", command=self.open_quick_audit)
        btn_qa.pack(anchor="w")

    def _build_tools_grid(self) -> None:
        """Create responsive grid of launch cards for each tool in the suite."""
        container = ttk.Frame(self, padding=(16, 4))
        container.pack(fill="both", expand=True)

        lbl_section = ttk.Label(container, text="HERRAMIENTAS Y PROGRAMAS DE LA SUITE", font=FONTS["title_small"], foreground=COLORS["accent_cyan"])
        lbl_section.pack(anchor="w", pady=(4, 10))

        # Scrollable canvas for cards
        canvas = tk.Canvas(container, bg=COLORS["bg_dark"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Tool specifications
        tools_catalog = [
            {
                "id": "netsentry",
                "name": "NetSentry",
                "version": "1.0.0",
                "category": "REDES & WEB",
                "icon": "netsentry.png",
                "desc": "Escáner concurrente de puertos TCP (15 puertos comunes en < 0.8s), banner grabbing ligero y verificación de las 6 cabeceras de seguridad recomendadas por OWASP (HSTS, CSP, X-Frame-Options).",
            },
            {
                "id": "logsentinel",
                "name": "LogSentinel",
                "version": "1.0.0",
                "category": "FORENSE & IDS",
                "icon": "logsentinel.png",
                "desc": "Ingesta y análisis forense de registros (auth.log, access.log), detección de ataques de fuerza bruta SSH, Directory Traversal y escáneres maliciosos con generación de reglas de cortafuegos UFW/iptables.",
            },
            {
                "id": "certsentry",
                "name": "CertSentry",
                "version": "1.0.0",
                "category": "CRIPTOGRAFÍA & PKI",
                "icon": "certsentry.png",
                "desc": "Auditoría preventiva de caducidad de certificados SSL/TLS X.509 (alertas 30/15/7 días), verificación de la cadena de confianza y detección de soporte a protocolos obsoletos (TLS 1.0/1.1).",
            },
            {
                "id": "subnetsweep",
                "name": "SubnetSweep",
                "version": "1.0.0",
                "category": "INFRAESTRUCTURA",
                "icon": "subnetsweep.png",
                "desc": "Descubrimiento de activos en subredes locales (/24) mediante sondas TCP/ICMP concurrentes, lectura de tablas ARP y mapeo de fabricantes según prefijos OUI IEEE (Raspberry Pi, Cisco, etc.).",
            },
            {
                "id": "integrityguard",
                "name": "IntegrityGuard",
                "version": "1.0.0",
                "category": "HIDS & FORENSE",
                "icon": "integrityguard.png",
                "desc": "Sistema de detección de intrusiones basado en host (HIDS) que genera líneas base con firmas criptográficas SHA-256 para alertar en milisegundos de modificaciones o inyecciones no autorizadas.",
            },
            {
                "id": "dnsprobe",
                "name": "DnsProbe",
                "version": "1.0.0",
                "category": "DNS & EMAIL",
                "icon": "dnsprobe.png",
                "desc": "Reconocimiento y auditoría de registros DNS públicos y defensa contra suplantación de correo electrónico (verificación estricta de políticas SPF, DMARC y validación de firma DNSSEC).",
            },
            {
                "id": "trafficsentry",
                "name": "TrafficSentry",
                "version": "1.1.0",
                "category": "HOST & SOCKETS",
                "icon": "trafficsentry.png",
                "desc": "Auditoría de conexiones activas del sistema operativo y detección de daemons o servicios sensibles expuestos a 0.0.0.0 (todas las interfaces) en lugar de localhost.",
            },
        ]

        # 2 columns grid
        cols = 2
        for idx, t in enumerate(tools_catalog):
            r = idx // cols
            c = idx % cols
            self._create_tool_card(scrollable_frame, t, row=r, col=c)

    def _create_tool_card(self, parent: ttk.Frame, info: dict, row: int, col: int) -> None:
        """Create individual program card in the launcher grid."""
        card = ttk.Frame(parent, padding=14, style="Card.TFrame")
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        parent.columnconfigure(col, weight=1)

        # Top row inside card: Icon + Name + Category Tag
        top_row = ttk.Frame(card, style="Card.TFrame")
        top_row.pack(fill="x", pady=(0, 6))

        icon_path = os.path.join("assets", "logos", info["icon"])
        tool_icon = load_icon(icon_path, size=(48, 48))
        if tool_icon:
            icon_lbl = ttk.Label(top_row, image=tool_icon, style="Card.TLabel")
            icon_lbl.image = tool_icon
            icon_lbl.pack(side="left", padx=(0, 12))

        title_box = ttk.Frame(top_row, style="Card.TFrame")
        title_box.pack(side="left", fill="y")

        lbl_name = ttk.Label(title_box, text=f"{info['name']} v{info['version']}", font=FONTS["title_small"], foreground=COLORS["accent_cyan"], style="Card.TLabel")
        lbl_name.pack(anchor="w")

        lbl_cat = ttk.Label(title_box, text=info["category"], font=FONTS["caption"], foreground=COLORS["accent_blue"], style="Card.TLabel")
        lbl_cat.pack(anchor="w")

        # Status indicator badge
        badge = tk.Label(top_row, text="LISTO", bg=COLORS["surface"], fg=COLORS["accent_green"], font=FONTS["caption"], padx=8, pady=2)
        badge.pack(side="right")

        # Description
        lbl_desc = ttk.Label(card, text=info["desc"], font=FONTS["caption"], foreground=COLORS["text_secondary"], wraplength=440, justify="left", style="Card.TLabel")
        lbl_desc.pack(fill="x", pady=(4, 10))

        # Bottom row: Action button to launch in independent window
        bottom_row = ttk.Frame(card, style="Card.TFrame")
        bottom_row.pack(fill="x")

        btn_launch = ttk.Button(
            bottom_row,
            text=f"Abrir {info['name']} ▶",
            style="Primary.TButton",
            command=lambda tid=info["id"]: self.launch_tool(tid)
        )
        btn_launch.pack(side="right")

    def _build_footer(self) -> None:
        """Suite accreditation and status footer."""
        footer = ttk.Frame(self, padding=(20, 8), style="Surface.TFrame")
        footer.pack(fill="x", side="bottom")

        lbl_author = ttk.Label(
            footer,
            text="HFS-Sentry Suite | Autor: Hamza El Fathi Sofyani | Certificado en Ciberseguridad Cisco Networking Academy | Grado Ing. Informática (UNED)",
            font=FONTS["caption"],
            background=COLORS["surface"],
            foreground=COLORS["text_secondary"]
        )
        lbl_author.pack(side="left")

        lbl_lic = ttk.Label(
            footer,
            text="Código Libre — Licencia MIT | 100% Local & Desconectado",
            font=FONTS["caption"],
            background=COLORS["surface"],
            foreground=COLORS["accent_green"]
        )
        lbl_lic.pack(side="right")

    def open_quick_audit(self) -> None:
        """Open the 1-Click System Quick Audit dialog."""
        from sentry.ui.quick_audit_dialog import QuickAuditDialog
        QuickAuditDialog(self)

    def launch_tool(self, tool_id: str, prefill_data: Optional[str] = None) -> Any:
        """Open the requested tool in a dedicated, independent desktop window with optional prefilled target."""
        window_cls = TOOL_WINDOW_MAP.get(tool_id)
        if not window_cls:
            messagebox.showerror("Error", f"No se encontró la ventana gráfica para la herramienta '{tool_id}'.")
            return None

        # Open in new independent desktop window
        win_instance = window_cls(master=self)
        if prefill_data and hasattr(win_instance, "apply_prefill"):
            win_instance.apply_prefill(prefill_data)
        win_instance.focus_set()

        if tool_id not in self.active_tool_windows:
            self.active_tool_windows[tool_id] = []
        self.active_tool_windows[tool_id].append(win_instance)
        return win_instance

    def _check_network_status(self) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect(("1.1.1.1", 53))
            s.close()
            messagebox.showinfo("Conectividad", "Conectividad de red activa: Salida a Internet y resolución de sockets operativa.")
        except Exception as e:
            messagebox.showwarning("Aviso de Red", f"Sin salida exterior o entorno local aislado: {e}\n(Las herramientas de auditoría interna y análisis de logs siguen funcionando al 100%).")

    def _show_suite_settings(self) -> None:
        from sentry.core.config import load_config, save_config

        cfg = load_config()

        dlg = tk.Toplevel(self)
        dlg.title("Preferencias Globales — HFS-Sentry Suite")
        dlg.geometry("500x440")
        dlg.minsize(440, 360)
        dlg.configure(bg=COLORS["bg_dark"])
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(dlg, text="Preferencias de la Suite", font=FONTS["title_medium"], foreground=COLORS["accent_cyan"]).pack(pady=12)

        box = ttk.Frame(dlg, padding=16, style="Card.TFrame")
        box.pack(fill="both", expand=True, padx=16, pady=8)

        # 1. Sound alerts toggle
        var_sound = tk.BooleanVar(value=cfg.get("sound_alerts_enabled", True))
        chk_sound = ttk.Checkbutton(box, text="Activar alertas y avisos sonoros (Audio Cues)", variable=var_sound)
        chk_sound.pack(anchor="w", pady=(0, 10))

        # 2. Default duration
        ttk.Label(box, text="Duración predeterminada de ventana temporal (segundos):", style="Card.TLabel").pack(anchor="w", pady=(4, 2))
        spin_dur = ttk.Spinbox(box, from_=5, to=300, width=8)
        spin_dur.set(str(int(cfg.get("default_duration_seconds", 30))))
        spin_dur.pack(anchor="w", pady=(0, 10))

        # 3. Network timeout
        ttk.Label(box, text="Timeout predeterminado para sockets (segundos):", style="Card.TLabel").pack(anchor="w", pady=(4, 2))
        spin_timeout = ttk.Spinbox(box, from_=0.5, to=30.0, increment=0.5, width=8)
        spin_timeout.set(str(float(cfg.get("network_timeout_seconds", 3.0))))
        spin_timeout.pack(anchor="w", pady=(0, 10))

        ttk.Label(box, text="• Cero dependencias externas (Python Estándar + Tkinter)", font=FONTS["caption"], style="CardSecondary.TLabel").pack(anchor="w")

        def _save_and_close():
            try:
                cfg["sound_alerts_enabled"] = var_sound.get()
                cfg["default_duration_seconds"] = int(spin_dur.get())
                cfg["network_timeout_seconds"] = float(spin_timeout.get())
                save_config(cfg)
                messagebox.showinfo("Preferencias Guardadas", "Configuración actualizada y guardada correctamente.", parent=dlg)
                dlg.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar la configuración: {e}", parent=dlg)

        btn_box = ttk.Frame(dlg)
        btn_box.pack(fill="x", padx=16, pady=12)
        ttk.Button(btn_box, text="Guardar Preferencias", style="Primary.TButton", command=_save_and_close).pack(side="right", padx=4)
        ttk.Button(btn_box, text="Cancelar", command=dlg.destroy).pack(side="right", padx=4)

    def _open_github(self) -> None:
        webbrowser.open_new_tab("https://github.com/faathii/HFS-Sentry")

    def _open_contributing(self) -> None:
        webbrowser.open_new_tab("https://github.com/faathii/HFS-Sentry/blob/main/CONTRIBUTING.md")

    def _show_about(self) -> None:
        msg = (
            f"HFS-Sentry Suite Hub v{__version__}\n\n"
            "Suite de Herramientas de Ciberseguridad & Diagnóstico de Infraestructuras\n\n"
            "Autor: Hamza El Fathi Sofyani\n"
            "• Certificado en Ciberseguridad por Cisco Networking Academy\n"
            "• Grado en Ingeniería Informática (UNED)\n"
            "• Repositorio: https://github.com/faathii/HFS-Sentry\n\n"
            "Licencia: MIT (Código Abierto)"
        )
        messagebox.showinfo("Acerca de HFS-Sentry", msg)


def main() -> None:
    """Launch Desktop Suite application."""
    app = SentrySuiteApp()
    app.mainloop()


if __name__ == "__main__":
    main()

