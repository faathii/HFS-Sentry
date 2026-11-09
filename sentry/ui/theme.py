"""Design system, color palette and ttk styles for HFS-Sentry Desktop Suite."""

import os
import tkinter as tk
from tkinter import ttk
from typing import Dict, Optional
from PIL import Image, ImageTk

# Cyber-Security Pro Dark Palette
COLORS = {
    "bg_dark": "#0a111e",        # Deep workspace canvas
    "bg_card": "#121d30",        # Floating cards & frames
    "bg_input": "#1a2a44",       # Inputs and text boxes
    "bg_hover": "#223759",       # Hover state
    "surface": "#1e314f",        # Elevated panels
    "border": "#274268",         # Subtle outlines
    "accent_cyan": "#00d2ff",    # Primary action / cyber glow
    "accent_blue": "#2979ff",    # Secondary accent
    "accent_green": "#00e676",   # Success / Pass
    "accent_red": "#ff5252",     # Critical / Fail
    "accent_yellow": "#ffd600",  # Notice / Warning
    "text_primary": "#ffffff",   # Crisp headlines & labels
    "text_secondary": "#9fb3c8", # Descriptive subtitles
    "text_dim": "#627d98",       # De-emphasized notes
    "terminal_bg": "#050911",    # Pure dark terminal console
    "terminal_fg": "#40c4ff",    # Neon terminal text
}

FONTS = {
    "title_large": ("Segoe UI", 16, "bold"),
    "title_medium": ("Segoe UI", 13, "bold"),
    "title_small": ("Segoe UI", 11, "bold"),
    "body": ("Segoe UI", 10),
    "body_bold": ("Segoe UI", 10, "bold"),
    "caption": ("Segoe UI", 9),
    "code": ("Consolas", 10),
    "code_small": ("Consolas", 9),
    "code_sm": ("Consolas", 9),
}

_IMAGE_CACHE: Dict[str, ImageTk.PhotoImage] = {}


def load_icon(path: str, size: tuple = (48, 48)) -> Optional[ImageTk.PhotoImage]:
    """Load, resize and cache image with transparency support."""
    key = f"{path}_{size[0]}x{size[1]}"
    if key in _IMAGE_CACHE:
        return _IMAGE_CACHE[key]

    if not os.path.isfile(path):
        return None

    try:
        img = Image.open(path).convert("RGBA")
        img = img.resize(size, Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        _IMAGE_CACHE[key] = photo
        return photo
    except Exception:
        return None


def apply_suite_theme(root: tk.Tk) -> None:
    """Apply unified high-contrast dark cybersecurity theme to Tk and ttk widgets."""
    style = ttk.Style(root)

    # Use clam or default engine for full color control
    available_themes = style.theme_names()
    if "clam" in available_themes:
        style.theme_use("clam")

    root.configure(bg=COLORS["bg_dark"])

    # General TTK base configs
    style.configure(
        ".",
        background=COLORS["bg_dark"],
        foreground=COLORS["text_primary"],
        font=FONTS["body"],
    )

    # TFrame
    style.configure("TFrame", background=COLORS["bg_dark"])
    style.configure("Card.TFrame", background=COLORS["bg_card"], relief="flat")
    style.configure("Surface.TFrame", background=COLORS["surface"], relief="flat")

    # TLabel
    style.configure("TLabel", background=COLORS["bg_dark"], foreground=COLORS["text_primary"], font=FONTS["body"])
    style.configure("Card.TLabel", background=COLORS["bg_card"], foreground=COLORS["text_primary"])
    style.configure("Secondary.TLabel", background=COLORS["bg_dark"], foreground=COLORS["text_secondary"], font=FONTS["caption"])
    style.configure("CardSecondary.TLabel", background=COLORS["bg_card"], foreground=COLORS["text_secondary"], font=FONTS["caption"])
    style.configure("Header.TLabel", background=COLORS["bg_dark"], foreground=COLORS["accent_cyan"], font=FONTS["title_large"])
    style.configure("CardHeader.TLabel", background=COLORS["bg_card"], foreground=COLORS["text_primary"], font=FONTS["title_small"])

    # TButton
    style.configure(
        "TButton",
        background=COLORS["bg_input"],
        foreground=COLORS["text_primary"],
        bordercolor=COLORS["border"],
        focusthickness=0,
        padding=6,
        font=FONTS["body_bold"],
    )
    style.map(
        "TButton",
        background=[("active", COLORS["bg_hover"]), ("pressed", COLORS["surface"])],
        foreground=[("active", COLORS["accent_cyan"])],
    )

    # Primary Accent Button
    style.configure(
        "Primary.TButton",
        background=COLORS["accent_blue"],
        foreground="#ffffff",
        bordercolor=COLORS["accent_cyan"],
        focusthickness=0,
        padding=(12, 6),
        font=FONTS["body_bold"],
    )
    style.map(
        "Primary.TButton",
        background=[("active", COLORS["accent_cyan"]), ("pressed", COLORS["surface"])],
        foreground=[("active", "#000000")],
    )

    # Danger / Stop Button
    style.configure(
        "Danger.TButton",
        background="#781717",
        foreground="#ffffff",
        bordercolor=COLORS["accent_red"],
        padding=(10, 5),
        font=FONTS["body_bold"],
    )
    style.map("Danger.TButton", background=[("active", COLORS["accent_red"])])

    # TEntry
    style.configure(
        "TEntry",
        fieldbackground=COLORS["bg_input"],
        foreground=COLORS["text_primary"],
        insertcolor=COLORS["accent_cyan"],
        bordercolor=COLORS["border"],
        padding=5,
    )

    # Notebook Tabs
    style.configure(
        "TNotebook",
        background=COLORS["bg_dark"],
        tabmargins=[2, 5, 2, 0],
    )
    style.configure(
        "TNotebook.Tab",
        background=COLORS["bg_card"],
        foreground=COLORS["text_secondary"],
        padding=[14, 6],
        font=FONTS["body_bold"],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLORS["surface"]), ("active", COLORS["bg_hover"])],
        foreground=[("selected", COLORS["accent_cyan"]), ("active", COLORS["text_primary"])],
    )

    # Treeview (Data Tables)
    style.configure(
        "Treeview",
        background=COLORS["bg_card"],
        foreground=COLORS["text_primary"],
        fieldbackground=COLORS["bg_card"],
        rowheight=26,
        font=FONTS["code_small"],
        bordercolor=COLORS["border"],
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["accent_blue"])],
        foreground=[("selected", "#ffffff")],
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["surface"],
        foreground=COLORS["accent_cyan"],
        font=FONTS["body_bold"],
        padding=4,
        relief="flat",
    )

    # Progressbar
    style.configure(
        "Horizontal.TProgressbar",
        troughcolor=COLORS["bg_input"],
        background=COLORS["accent_cyan"],
        bordercolor=COLORS["border"],
    )

