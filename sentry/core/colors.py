"""Terminal color formatting utility using standard ANSI escape codes.
Automatically disables colors if stdout is not a TTY or if NO_COLOR is set.
"""

import os
import sys

_NO_COLOR = os.getenv("NO_COLOR") is not None
_IS_TTY = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
_COLOR_ENABLED = _IS_TTY and not _NO_COLOR


def _wrap(code: str, text: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(text: str) -> str:
    return _wrap("31", text)


def green(text: str) -> str:
    return _wrap("32", text)


def yellow(text: str) -> str:
    return _wrap("33", text)


def blue(text: str) -> str:
    return _wrap("34", text)


def cyan(text: str) -> str:
    return _wrap("36", text)


def bold(text: str) -> str:
    return _wrap("1", text)


def dim(text: str) -> str:
    return _wrap("2", text)
