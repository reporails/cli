"""Bundled configuration files for reporails CLI.

This package contains CLI-owned configuration:
- models/: an in-package copy of the ML model directory used by dev checkouts
  and CI. The published wheel is lean and does not carry it; the mapper's
  ``model_store`` resolves and fetches the model set.
"""

from __future__ import annotations

from pathlib import Path


def get_bundled_path() -> Path:
    """Get path to bundled configuration directory."""
    return Path(__file__).parent


def get_lexicon_path() -> Path:
    """Get path to the bundled lexicon directory.

    Holds the mapper's externalized data files (e.g. ``markdown_tokens.yml``),
    read via ``core/mapper/lexicon.py``. Shipped inside the wheel as tracked
    package data.
    """
    return get_bundled_path() / "lexicon"


def get_xray_path() -> Path:
    """Get path to the bundled x-ray page folder (`index.html`, `xray.js`, `xray.css`, `fonts/`)."""
    return get_bundled_path() / "xray"


def get_prices_path(agent: str) -> Path:
    """Get path to the bundled list prices of an agent's models (`prices/<agent>.yml`)."""
    return get_bundled_path() / "prices" / f"{agent}.yml"
