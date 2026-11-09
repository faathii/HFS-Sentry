"""Base window architecture for independent desktop tools in HFS-Sentry."""

from datetime import datetime
import json
import os
import sys
import threading
import time
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
        self.geometry("1080x720")
        self.minsize(860, 580)
        self.configure(bg=COLORS["bg_dark"])

        self.worker_thread: Optional[threading.Thread] = None
        self.stop_requested = threading.Event()
        self.latest_results: Optional[Dict[str, Any]] = None
        self._stopwatch_running = False
        self._stopwatch_start_time = 0.0
        self._stopwatch_target_duration = 0.0

        # Set window icon if available
        try:
            icon_path = os.path.join("assets", "logos", self.icon_filename)
            self.tool_photo = load_icon(icon_path, size=(32, 32))
            if self.tool_photo:
                self.iconphoto(False, self.tool_photo)
        except Exception:
            self.tool_photo = None

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
        file_menu.add_command(label="Exportar Tabla (CSV)", command=self.export_results_csv)
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
        if hasattr(self, "tree") and isinstance(self.tree, ttk.Treeview):
            self.enable_treeview_sorting(self.tree)
            self.enable_treeview_context_menu(self.tree)

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
        """Bottom status bar with digital stopwatch, progress bar and timestamp."""
        status_frame = ttk.Frame(self, padding=(12, 6), style="Surface.TFrame")
        status_frame.pack(fill="x", side="bottom")

        self.lbl_status = ttk.Label(status_frame, text="Listo.", font=FONTS["caption"], background=COLORS["surface"])
        self.lbl_status.pack(side="left")

        # Digital Chronometer Stopwatch right next to progress bar
        self.lbl_stopwatch = ttk.Label(
            status_frame,
            text="⏱️ 00:00",
            font=FONTS["code_small"],
            foreground=COLORS["accent_cyan"],
            background=COLORS["surface"]
        )
        self.lbl_stopwatch.pack(side="right", padx=(8, 4))

        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="indeterminate", length=160)
        self.progress_bar.pack(side="right", padx=6)

    def start_stopwatch(self, target_duration: float = 0.0) -> None:
        """Start the digital chronometer in the status bar."""
        self._stopwatch_start_time = time.time()
        self._stopwatch_target_duration = target_duration
        self._stopwatch_running = True
        self._tick_stopwatch()

    def _tick_stopwatch(self) -> None:
        if not getattr(self, "_stopwatch_running", False):
            return

        elapsed = time.time() - self._stopwatch_start_time
        mins, secs = divmod(int(elapsed), 60)
        time_str = f"{mins:02d}:{secs:02d}"

        if 0 < self._stopwatch_target_duration < 100000:
            t_mins, t_secs = divmod(int(self._stopwatch_target_duration), 60)
            display = f"⏱️ {time_str} / {t_mins:02d}:{t_secs:02d}"
        else:
            display = f"⏱️ {time_str}"

        self.lbl_stopwatch.config(text=display)
        self.after(200, self._tick_stopwatch)

    def stop_stopwatch(self, final_text: Optional[str] = None) -> None:
        """Stop the digital chronometer."""
        self._stopwatch_running = False
        if final_text:
            self.lbl_stopwatch.config(text=final_text)
        elif hasattr(self, "_stopwatch_start_time") and self._stopwatch_start_time > 0:
            elapsed = time.time() - self._stopwatch_start_time
            mins, secs = divmod(int(elapsed), 60)
            self.lbl_stopwatch.config(text=f"⏱️ {mins:02d}:{secs:02d} (Listo)")

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
            elif state == "stopped":
                self.badge_status.config(text="DETENIDO", fg=COLORS["accent_yellow"], bg=COLORS["surface"])
                self.progress_bar.stop()
            else:
                self.badge_status.config(text="LISTO", fg=COLORS["accent_green"], bg=COLORS["surface"])
                self.progress_bar.stop()
        self.after(0, _update)

    def execute_async(self, worker_fn: Callable, target_duration: float = 0.0) -> None:
        """Launch background diagnostic thread to ensure UI remains completely responsive."""
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Análisis en curso", "Ya hay un diagnóstico en ejecución. Deténgalo antes de iniciar uno nuevo.")
            return

        self.stop_requested.clear()
        self.start_stopwatch(target_duration)
        self.set_status("Ejecutando diagnóstico...", state="running")

        def _run_wrapper():
            try:
                worker_fn()
            except Exception as e:
                self.log(f"[ERROR CRÍTICO] {e}")
                self.set_status(f"Error: {e}", state="error")
                self.stop_stopwatch("⏱️ Error")
            finally:
                if self.stop_requested.is_set():
                    self.set_status("Diagnóstico detenido por el usuario.", state="stopped")
                    self.stop_stopwatch("⏱️ Detenido")
                else:
                    self.set_status("Análisis finalizado.", state="success")
                    self.stop_stopwatch()
                    try:
                        from sentry.ui.notifications import notify_user
                        notify_user(
                            title=f"{self.tool_title}",
                            message="Diagnóstico completado. Revise los resultados estructurados.",
                            level="success"
                        )
                    except Exception:
                        pass

        self.worker_thread = threading.Thread(target=_run_wrapper, daemon=True)
        self.worker_thread.start()

    def stop_analysis(self) -> None:
        """Request immediate worker thread cancellation."""
        self.stop_requested.set()
        self.log("[!] Detención solicitada por el operador.")
        self.set_status("Deteniendo diagnóstico...", state="stopped")
        self.stop_stopwatch("⏱️ Detenido")

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
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.latest_results, f, indent=2)
                messagebox.showinfo("Exportación Exitosa", f"Resultados guardados correctamente en:\n{path}")
            except Exception as e:
                messagebox.showerror("Error al Guardar", f"No se pudo guardar el archivo JSON:\n{e}")

    def export_results_csv(self) -> None:
        """Export current structured results table to CSV file."""
        if not hasattr(self, "tree") or not self.tree.get_children():
            messagebox.showinfo("Sin Datos", "No hay filas en la tabla para exportar a CSV.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title=f"Exportar Tabla CSV - {self.tool_title}",
            initialfile=f"{self.tool_id}_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if path:
            try:
                import csv
                cols = self.tree["columns"]
                headers = [self.tree.heading(c)["text"] for c in cols]
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    for item_id in self.tree.get_children():
                        row_vals = self.tree.item(item_id, "values")
                        writer.writerow(row_vals)
                messagebox.showinfo("Exportación Exitosa", f"Datos CSV exportados correctamente en:\n{path}")
            except Exception as e:
                messagebox.showerror("Error de Exportación", f"No se pudo guardar el archivo CSV:\n{e}")

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
            try:
                html_content = generate_html_report(self.latest_results, title=f"Auditoría Técnica — {self.tool_title}")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                messagebox.showinfo("Informe HTML Listo", f"Informe ejecutivo exportado exitosamente:\n{path}")
            except Exception as e:
                messagebox.showerror("Error al Guardar", f"No se pudo guardar el informe HTML:\n{e}")

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
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Exportación Exitosa", f"Registro guardado correctamente en:\n{path}")
            except Exception as e:
                messagebox.showerror("Error al Guardar", f"No se pudo guardar el registro:\n{e}")

    def apply_prefill(self, value: str) -> None:
        """Override in subclasses to prefill target inputs when pivoting between tools."""
        pass

    def enable_treeview_sorting(self, tree: ttk.Treeview) -> None:
        """Enable click-on-heading sorting for all columns with type-aware logic."""
        for col in tree["columns"]:
            tree.heading(col, command=lambda c=col: self._sort_column(tree, c, False))

    def _sort_column(self, tree: ttk.Treeview, col: str, reverse: bool) -> None:
        items = list(tree.get_children(""))
        if not items:
            return

        def _sort_key(item_id: str):
            val = str(tree.set(item_id, col)).strip()
            val_upper = val.upper()

            # 1. Risk ordering
            risk_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
            if val_upper in risk_map:
                return (0, risk_map[val_upper], "")

            # 2. Status ordering
            if "ACTIVO" in val_upper:
                return (1, 0, "")
            elif "LISTEN" in val_upper:
                return (1, 1, "")
            elif "CERRADO" in val_upper or "INACTIVO" in val_upper:
                return (1, 2, "")

            # 3. Numeric (duration "3.2s", latency "14.5 ms", port 80, size "1024 B")
            clean_num = val.replace("s", "").replace("ms", "").replace("B", "").replace("%", "").strip()
            try:
                num = float(clean_num)
                return (2, num, "")
            except ValueError:
                pass

            # 4. Standard string
            return (3, val.lower(), "")

        sorted_items = sorted(items, key=_sort_key, reverse=reverse)
        for index, item_id in enumerate(sorted_items):
            tree.move(item_id, "", index)

        # Toggle sort order on next click and update indicator arrow
        for c in tree["columns"]:
            heading_text = tree.heading(c)["text"].replace(" ▲", "").replace(" ▼", "")
            if c == col:
                arrow = " ▼" if reverse else " ▲"
                tree.heading(c, text=heading_text + arrow, command=lambda: self._sort_column(tree, c, not reverse))
            else:
                tree.heading(c, text=heading_text, command=lambda _c=c: self._sort_column(tree, _c, False))

    def enable_treeview_context_menu(self, tree: ttk.Treeview) -> None:
        """Attach right-click context menu with copy actions and cross-tool pivots."""
        menu = tk.Menu(
            self,
            tearoff=0,
            bg=COLORS["bg_card"],
            fg=COLORS["text_primary"],
            activebackground=COLORS["accent_blue"],
            activeforeground="#ffffff",
        )

        def _on_right_click(event):
            row_id = tree.identify_row(event.y)
            if not row_id:
                return

            tree.selection_set(row_id)
            vals = tree.item(row_id, "values")
            if not vals:
                return

            # Detect target IP, port, or host
            target_ip = None
            for v in vals:
                v_str = str(v).strip()
                if ":" in v_str and not v_str.startswith("["):
                    candidate = v_str.split(":")[0]
                else:
                    candidate = v_str

                parts = candidate.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
                    target_ip = candidate
                    break
                elif "." in candidate and not candidate.endswith(".") and not candidate.startswith("."):
                    target_ip = candidate
                    break

            menu.delete(0, "end")
            menu.add_command(label="📋 Copiar Valor", command=lambda: self._copy_to_clipboard(vals[0] if vals else ""))
            menu.add_command(label="📋 Copiar Fila Completa", command=lambda: self._copy_to_clipboard(" | ".join(str(v) for v in vals)))

            if target_ip:
                menu.add_separator()
                menu.add_command(label=f"🎯 Copiar IP / Objetivo: {target_ip}", command=lambda: self._copy_to_clipboard(target_ip))
                menu.add_separator()
                menu.add_command(
                    label=f"⚡ Auditar Puertos con NetSentry ({target_ip})",
                    command=lambda: self._pivot_to_tool("netsentry", target_ip)
                )
                menu.add_command(
                    label=f"🌐 Ver Registros DNS con DnsProbe ({target_ip})",
                    command=lambda: self._pivot_to_tool("dnsprobe", target_ip)
                )
                menu.add_command(
                    label=f"🔒 Inspeccionar Certificado con CertSentry ({target_ip})",
                    command=lambda: self._pivot_to_tool("certsentry", target_ip)
                )
                menu.add_command(
                    label=f"📡 Barrido de Subred con SubnetSweep ({target_ip})",
                    command=lambda: self._pivot_to_tool("subnetsweep", target_ip)
                )

            menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", _on_right_click)
        tree.bind("<Button-2>", _on_right_click)

    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status(f"Copiado al portapapeles: {text[:45]}...", state="success")

    def _pivot_to_tool(self, tool_id: str, target: str) -> None:
        """Cross-tool pivot launcher."""
        app = getattr(self, "master", None)
        if app and hasattr(app, "launch_tool"):
            app.launch_tool(tool_id, prefill_data=target)
        else:
            try:
                from sentry.ui.app import TOOL_WINDOW_MAP
                cls = TOOL_WINDOW_MAP.get(tool_id)
                if cls:
                    w = cls(master=self.master)
                    w.apply_prefill(target)
                    w.focus_set()
            except Exception as e:
                self.log(f"[ERROR] Error al cambiar a herramienta {tool_id}: {e}")

    def show_settings_dialog(self) -> None:
        """Display interactive user preferences dialog with persistent storage."""
        from sentry.core.config import load_config, save_config

        cfg = load_config()

        dlg = tk.Toplevel(self)
        dlg.title(f"Ajustes & Preferencias — HFS-Sentry")
        dlg.geometry("500x380")
        dlg.minsize(440, 340)
        dlg.configure(bg=COLORS["bg_dark"])
        dlg.transient(self)
        dlg.grab_set()

        lbl = ttk.Label(dlg, text="Preferencias Generales de la Suite", font=FONTS["title_small"])
        lbl.pack(pady=(16, 8))

        box = ttk.Frame(dlg, padding=16, style="Card.TFrame")
        box.pack(fill="both", expand=True, padx=16, pady=8)

        # 1. Sound alerts toggle
        var_sound = tk.BooleanVar(value=cfg.get("sound_alerts_enabled", True))
        chk_sound = ttk.Checkbutton(
            box,
            text="Habilitar avisos sonoros de sistema (Cues acústicos para alertas críticas y fin de auditoría)",
            variable=var_sound
        )
        chk_sound.pack(anchor="w", pady=(0, 14))

        # 2. Default duration
        ttk.Label(box, text="Duración por defecto de ventana temporal:", style="Card.TLabel").pack(anchor="w", pady=(0, 4))
        combo_dur = ttk.Combobox(
            box,
            values=["30 segundos (Recomendado)", "10 segundos", "60 segundos", "Instantáneo (1s)", "Monitoreo Continuo"],
            state="readonly",
            width=32
        )
        cur_dur = cfg.get("default_duration_seconds", 30.0)
        if cur_dur == 10.0:
            combo_dur.current(1)
        elif cur_dur == 60.0:
            combo_dur.current(2)
        elif cur_dur <= 1.0:
            combo_dur.current(3)
        elif cur_dur >= 100000:
            combo_dur.current(4)
        else:
            combo_dur.current(0)
        combo_dur.pack(anchor="w", pady=(0, 14))

        # 3. Default Timeout
        ttk.Label(box, text="Timeout por defecto para conexiones de red (segundos):", style="Card.TLabel").pack(anchor="w", pady=(0, 4))
        entry_to = ttk.Entry(box, width=12)
        entry_to.insert(0, str(cfg.get("default_timeout_seconds", 3.0)))
        entry_to.pack(anchor="w", pady=(0, 14))

        def _save_prefs():
            try:
                to_val = float(entry_to.get().strip())
            except ValueError:
                to_val = 3.0

            dur_str = combo_dur.get()
            if "10s" in dur_str or "10 seg" in dur_str:
                dur_val = 10.0
            elif "60s" in dur_str or "60 seg" in dur_str:
                dur_val = 60.0
            elif "Instant" in dur_str:
                dur_val = 0.0
            elif "Continuo" in dur_str:
                dur_val = 999999.0
            else:
                dur_val = 30.0

            cfg["sound_alerts_enabled"] = var_sound.get()
            cfg["default_duration_seconds"] = dur_val
            cfg["default_timeout_seconds"] = to_val

            if save_config(cfg):
                messagebox.showinfo("Preferencias Guardadas", "Sus preferencias han sido guardadas con éxito.")
                dlg.destroy()
            else:
                messagebox.showerror("Error", "No se pudieron guardar las preferencias.")

        btn_row = ttk.Frame(dlg, style="Card.TFrame")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))

        btn_save = ttk.Button(btn_row, text="💾 Guardar Preferencias", style="Primary.TButton", command=_save_prefs)
        btn_save.pack(side="right", padx=4)

        btn_cancel = ttk.Button(btn_row, text="Cancelar", command=dlg.destroy)
        btn_cancel.pack(side="right", padx=4)

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

