"""Native cross-platform desktop toast notification engine.

Zero external dependencies (pure Python 3 standard library + Tkinter).
Displays floating dark-mode cyber notification banners with audio cues.
"""

import sys
import threading
import tkinter as tk
from sentry.ui.theme import COLORS, FONTS


def notify_user(title: str, message: str, level: str = "info", duration_ms: int = 4000) -> None:
    """Display non-blocking desktop toast banner with audio beep."""
    # System sound (Windows)
    try:
        if sys.platform == "win32":
            import winsound
            freq = winsound.MB_ICONASTERISK if level == "info" else winsound.MB_ICONEXCLAMATION
            winsound.MessageBeep(freq)
    except Exception:
        pass

    # Launch toast in main thread if possible, or via thread-safe handler
    try:
        def _create_toast():
            toast = tk.Toplevel()
            toast.overrideredirect(True)
            toast.attributes("-topmost", True)
            toast.configure(bg=COLORS["bg_card"], highlightthickness=1, highlightbackground=COLORS["accent_cyan"])

            # Positioning at bottom-right of screen
            screen_w = toast.winfo_screenwidth()
            screen_h = toast.winfo_screenheight()
            toast_w, toast_h = 360, 90
            x = screen_w - toast_w - 24
            y = screen_h - toast_h - 60
            toast.geometry(f"{toast_w}x{toast_h}+{x}+{y}")

            # Styling colors
            border_color = COLORS["accent_green"] if level == "success" else (
                COLORS["accent_red"] if level in ("error", "critical") else COLORS["accent_cyan"]
            )
            toast.configure(highlightbackground=border_color)

            # Content container
            pad_frame = tk.Frame(toast, bg=COLORS["bg_card"], padx=14, pady=10)
            pad_frame.pack(fill="both", expand=True)

            lbl_title = tk.Label(
                pad_frame,
                text=title,
                font=FONTS["title_small"],
                bg=COLORS["bg_card"],
                fg=border_color,
                anchor="w",
            )
            lbl_title.pack(fill="x")

            lbl_msg = tk.Label(
                pad_frame,
                text=message,
                font=FONTS["caption"],
                bg=COLORS["bg_card"],
                fg=COLORS["text_primary"],
                anchor="w",
                wraplength=330,
                justify="left",
            )
            lbl_msg.pack(fill="x", pady=(2, 0))

            # Click to dismiss
            toast.bind("<Button-1>", lambda e: toast.destroy())
            pad_frame.bind("<Button-1>", lambda e: toast.destroy())
            lbl_title.bind("<Button-1>", lambda e: toast.destroy())
            lbl_msg.bind("<Button-1>", lambda e: toast.destroy())

            # Auto-destroy after duration
            toast.after(duration_ms, lambda: _fade_and_destroy(toast))

        def _fade_and_destroy(t: tk.Toplevel):
            try:
                t.destroy()
            except Exception:
                pass

        _create_toast()
    except Exception:
        pass
