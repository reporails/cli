"""Character sets for terminal output.

Provides Unicode and ASCII character sets for box drawing and icons.
"""

from __future__ import annotations

import os

# ASCII mode: set AILS_ASCII=1 or pass ascii=True to format functions
ASCII_MODE = os.environ.get("AILS_ASCII", "").lower() in ("1", "true", "yes")

# Character sets for box drawing
UNICODE_CHARS = {
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
    "h": "═", "v": "║",
    "filled": "▓", "empty": "░",
    "check": "✓", "crit": "▲", "high": "!", "med": "○", "low": "·",
    "up": "↑", "down": "↓", "sep": "─",
}

ASCII_CHARS = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "h": "-", "v": "|",
    "filled": "#", "empty": ".",
    "check": "*", "crit": "!", "high": "!", "med": "o", "low": "-",
    "up": "^", "down": "v", "sep": "-",
}


def get_chars(ascii_mode: bool | None = None) -> dict[str, str]:
    """Get character set based on mode.

    Args:
        ascii_mode: Force ASCII mode. If None, uses AILS_ASCII env var.

    Returns:
        Character set dictionary
    """
    if ascii_mode is None:
        ascii_mode = ASCII_MODE
    return ASCII_CHARS if ascii_mode else UNICODE_CHARS
