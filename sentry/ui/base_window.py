"""Base window architecture for independent desktop tools in HFS-Sentry."""

from datetime import datetime
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, Optional

from sentry.ui.theme import COLORS, FONTS, load_icon


class BaseToolWindow(tk.Toplevel):
    """Abstract base desktop window for any tool in HFS-Sentry Suite.
    Runs as an independent, fully-featured desktop program with menu bar,
    asynchronous diagnostic execution, structured tables and live console.
    """

    tool_id: str = "base"
    tool_title: str = "HFS-Sentry Tool"
    tool_category: str = "General"
    tool_version: str = "1.0.0"
    icon_filename: str = "hfs_sentry.png"

    def __init__(self, master: Optional[tk.Tk] = None) -> None:
        super().__init__(master)
        self.title(f"{self.tool_title} - HFS-Sentry Suite")
        self.geometry("960x680")
        self.minsize(800, 560)
        self.configure(bg=COLORS["bg_dark"])

        self.worker_thread: Optional[threading.Thread] = None
        self.stop_requested = threading.Event()
        self.latest_results: Optional[Dict[str, Any]] = None

        # Set window icon if available
        icon_path = os.path.join("assets", "logos", self.icon_filename)
        self.tool_photo = load_icon(icon_path, size=(32, 32))
        if self.tool_photo:
            self.iconphoto(False, self.tool_photo)

        self._build_menu()
        self._build_header()
        self._build_ui_layout()
        self._build_status_bar()

        # Keyboard shortcuts
        self.bind("<Control-w>", lambda e: self.destroy())
        self.bind("<Control-s>", lambda e: self.export_results_json())
        self.bind("<Control-h>", lambda e: self.export_report_html())
        self.bind("<F5>", lambda e: self.start_analysis())
        self.bind("<Escape>", lambda e: self.stop_analysis())

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_menu(self) -> None:
        """Create professional native desktop menu bar."""
        menubar = tk.Menu(self, bg=COLORS["bg_card"], fg=COLORS["text_primary"])

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        file_menu.add_command(label="Nuevo Análisis\tCtrl+N", command=self.clear_results)
        file_menu.add_command(label="Exportar Resultados (JSON)\tCtrl+S", command=self.export_results_json)
        file_menu.add_command(label="Exportar Informe Ejecutivo (HTML)\tCtrl+H", command=self.export_report_html)
        file_menu.add_command(label="Exportar Informe (Texto)\tCtrl+E", command=self.export_report_txt)
        file_menu.add_separator()
        file_menu.add_command(label="Cerrar Ventana\tCtrl+W", command=self.destroy)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        # Actions Menu
        actions_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        actions_menu.add_command(label="Ejecutar Diagnóstico\tF5", command=self.start_analysis)
        actions_menu.add_command(label="Detener Diagnóstico\tEsc", command=self.stop_analysis)
        actions_menu.add_separator()
        actions_menu.add_command(label="Limpiar Consola y Resultados", command=self.clear_results)
        menubar.add_cascade(label="Acciones", menu=actions_menu)

        # Settings Menu
        settings_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        settings_menu.add_command(label="Preferencias del Módulo...", command=self.show_settings_dialog)
        menubar.add_cascade(label="Ajustes", menu=settings_menu)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        help_menu.add_command(label="Especificación Técnica", command=self.show_docs)
        help_menu.add_command(label=f"Acerca de {self.tool_title}", command=self.show_about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

        self.config(menu=menubar)

    def _build_header(self) -> None:
        """Top banner featuring tool icon, title, category and state badge."""
        header = ttk.Frame(self, padding=(16, 12), style="Card.TFrame")
        header.pack(fill="x", padx=12, pady=(10, 6))

        # Icon
        icon_path = os.path.join("assets", "logos", self.icon_filename)
        self.banner_icon = load_icon(icon_path, size=(42, 42))
        if self.banner_icon:
            icon_lbl = ttk.Label(header, image=self.banner_icon, style="Card.TLabel")
            icon_lbl.pack(side="left", padx=(0, 12))

        # Title block
        title_box = ttk.Frame(header, style="Card.TFrame")
        title_box.pack(side="left", fill="y")

        lbl_title = ttk.Label(title_box, text=self.tool_title, font=FONTS["title_medium"], foreground=COLORS["accent_cyan"], style="Card.TLabel")
        lbl_title.pack(anchor="w")

        lbl_cat = ttk.Label(title_box, text=f"Categoría: {self.tool_category}  |  Versión: {self.tool_version}", style="CardSecondary.TLabel")
        lbl_cat.pack(anchor="w")

        # Status badge
        self.badge_status = tk.Label(
            header,
            text="ESTADO: LISTO",
            bg=COLORS["surface"],
            fg=COLORS["accent_green"],
            font=FONTS["caption"],
            padx=10,
            pady=4,
            relief="flat",
        )
        self.badge_status.pack(side="right", padx=6)

    def _build_ui_layout(self) -> None:
        """Construct the core notebook tabs and shared widgets."""
        self.main_container = ttk.Frame(self, padding=(12, 4))
        self.main_container.pack(fill="both", expand=True)

        # Subclasses will insert their custom control frame here
        self.controls_frame = ttk.Frame(self.main_container, padding=(12, 10), style="Card.TFrame")
        self.controls_frame.pack(fill="x", pady=(0, 8))
        self.build_controls(self.controls_frame)

        # Tabs container
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Structured Results Table
        self.tab_table = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(self.tab_table, text="📊 Resultados Estructurados")
        self.build_results_table(self.tab_table)

        # Tab 2: Real-time Live Log Console
        self.tab_console = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(self.tab_console, text="💻 Consola en Tiempo Real")
        self._build_console_tab(self.tab_console)

        # Tab 3: Executive Summary
        self.tab_summary = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_summary, text="🛡️ Diagnóstico Ejecutivo")
        self._build_summary_tab(self.tab_summary)

    def _build_console_tab(self, parent: ttk.Frame) -> None:
        """Create high-density dark terminal console for live event streaming."""
        text_frame = ttk.Frame(parent)
        text_frame.pack(fill="both", expand=True)

        self.console_text = tk.Text(
            text_frame,
            bg=COLORS["terminal_bg"],
            fg=COLORS["terminal_fg"],
            insertbackground=COLORS["accent_cyan"],
            font=FONTS["code"],
            relief="flat",
            wrap="word",
        )
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.console_text.yview)
        self.console_text.configure(yscrollcommand=scroll.set)

        self.console_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] {self.tool_title} inicializado y listo para diagnóstico real.")

    def _build_summary_tab(self, parent: ttk.Frame) -> None:
        """Build executive diagnostic report tab."""
        self.summary_text = tk.Text(
            parent,
            bg=COLORS["bg_card"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            padx=12,
            pady=12,
        )
        self.summary_text.pack(fill="both", expand=True)
        self.summary_text.insert("end", "Ejecute un análisis para generar el informe de diagnóstico técnico.\n")

    def _build_status_bar(self) -> None:
        """Bottom status bar with progress bar and timestamp."""
        status_frame = ttk.Frame(self, padding=(12, 6), style="Surface.TFrame")
        status_frame.pack(fill="x", side="bottom")

        self.lbl_status = ttk.Label(status_frame, text="Listo.", font=FONTS["caption"], background=COLORS["surface"])
        self.lbl_status.pack(side="left")

        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="indeterminate", length=180)
        self.progress_bar.pack(side="right", padx=6)

    def log(self, message: str, tag: str = "info") -> None:
        """Thread-safe logging to the live console."""
        def _append():
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.console_text.insert("end", f"[{timestamp}] {message}\n")
            self.console_text.see("end")
        self.after(0, _append)

    def set_status(self, text: str, state: str = "running") -> None:
        """Update status bar label and header badge."""
        def _update():
            self.lbl_status.config(text=text)
            if state == "running":
                self.badge_status.config(text="ANALIZANDO...", fg=COLORS["accent_cyan"], bg=COLORS["surface"])
                self.progress_bar.start(10)
            elif state == "success":
                self.badge_status.config(text="COMPLETADO", fg=COLORS["accent_green"], bg=COLORS["surface"])
                self.progress_bar.stop()
            elif state == "error":
                self.badge_status.config(text="ERROR / FALLO", fg=COLORS["accent_red"], bg=COLORS["surface"])
                self.progress_bar.stop()
            else:
                self.badge_status.config(text="LISTO", fg=COLORS["accent_green"], bg=COLORS["surface"])
                self.progress_bar.stop()
        self.after(0, _update)

    def execute_async(self, worker_fn: Callable) -> None:
        """Launch background diagnostic thread to ensure UI remains completely responsive."""
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Análisis en curso", "Ya hay un diagnóstico en ejecución. Deténgalo antes de iniciar uno nuevo.")
            return

        self.stop_requested.clear()
        self.set_status("Ejecutando diagnóstico...", state="running")

        def _run_wrapper():
            try:
                worker_fn()
            except Exception as e:
                self.log(f"[ERROR CRÍTICO] {e}")
                self.set_status(f"Error: {e}", state="error")
            finally:
                if not self.stop_requested.is_set():
                    self.set_status("Análisis finalizado.", state="success")

        self.worker_thread = threading.Thread(target=_run_wrapper, daemon=True)
        self.worker_thread.start()

    def stop_analysis(self) -> None:
        """Request immediate worker thread cancellation."""
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_requested.set()
            self.log("[!] Detención solicitada por el operador.")
            self.set_status("Diagnóstico cancelado.", state="idle")

    def export_results_json(self) -> None:
        """Save analysis dataset as structured JSON file."""
        if not self.latest_results:
            messagebox.showinfo("Sin Datos", "No hay resultados de análisis disponibles para exportar.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")],
            title=f"Exportar Resultados - {self.tool_title}",
            initialfile=f"{self.tool_id}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.latest_results, f, indent=2)
            messagebox.showinfo("Exportación Exitosa", f"Resultados guardados correctamente en:\n{path}")

    def export_report_html(self) -> None:
        """Generate and save professional self-contained executive HTML audit report."""
        if not self.latest_results:
            messagebox.showinfo("Sin Datos", "Primero realice un diagnóstico para exportar el informe ejecutivo.")
            return

        from sentry.core.report import generate_html_report
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Informes HTML", "*.html"), ("Todos los archivos", "*.*")],
            title=f"Exportar Informe Ejecutivo HTML - {self.tool_title}",
            initialfile=f"{self.tool_id}_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        if path:
            html_content = generate_html_report(self.latest_results, title=f"Auditoría Técnica — {self.tool_title}")
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            messagebox.showinfo("Informe HTML Listo", f"Informe ejecutivo exportado exitosamente:\n{path}")

    def export_report_txt(self) -> None:
        """Export raw terminal console log to text file."""
        content = self.console_text.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Sin Datos", "La consola está vacía.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivos de Texto", "*.txt"), ("Todos los archivos", "*.*")],
            title="Exportar Registro de Consola",
            initialfile=f"{self.tool_id}_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Exportación Exitosa", f"Registro guardado correctamente en:\n{path}")

    def show_settings_dialog(self) -> None:
        """Display tool preferences dialog."""
        dlg = tk.Toplevel(self)
        dlg.title(f"Ajustes - {self.tool_title}")
        dlg.geometry("450x320")
        dlg.configure(bg=COLORS["bg_dark"])
        dlg.transient(self)
        dlg.grab_set()

        lbl = ttk.Label(dlg, text=f"Configuración de {self.tool_title}", font=FONTS["title_small"])
        lbl.pack(pady=12)

        box = ttk.Frame(dlg, padding=16, style="Card.TFrame")
        box.pack(fill="both", expand=True, padx=16, pady=8)

        ttk.Label(box, text="Configuración por defecto del motor:", style="Card.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(box, text="• Cero dependencias externas activas (Python 3 stdlib)", style="CardSecondary.TLabel").pack(anchor="w")
        ttk.Label(box, text="• Concurrencia mediante ThreadPoolExecutor", style="CardSecondary.TLabel").pack(anchor="w")
        ttk.Label(box, text="• Modos de exportación: JSON / TXT / Shell", style="CardSecondary.TLabel").pack(anchor="w")

        btn_close = ttk.Button(dlg, text="Cerrar", command=dlg.destroy)
        btn_close.pack(pady=12)

    def show_about(self) -> None:
        """Display about modal."""
        msg = f"{self.tool_title} v{self.tool_version}\n\nParte de HFS-Sentry Suite\nAutor: Hamza El Fathi Sofyani\nLicencia: MIT\n\nDiagnóstico de alta densidad sin dependencias externas."
        messagebox.showinfo(f"Acerca de {self.tool_title}", msg)

    def show_docs(self) -> None:
        """Display tool documentation."""
        self.notebook.select(self.tab_summary)

    def _on_close(self) -> None:
        self.stop_analysis()
        self.destroy()

    # Abstract methods to be implemented by tool windows
    def build_controls(self, parent: ttk.Frame) -> None:
        raise NotImplementedError

    def build_results_table(self, parent: ttk.Frame) -> None:
        raise NotImplementedError

    def start_analysis(self) -> None:
        raise NotImplementedError

    def clear_results(self) -> None:
        raise NotImplementedError

