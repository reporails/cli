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
