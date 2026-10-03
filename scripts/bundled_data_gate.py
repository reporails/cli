#!/usr/bin/env python3
"""Data-location gate: lexical / rule data lives only under ``bundled/``.

Import-linter polices module dependencies; it cannot see where a data file
lands. This gate enforces the companion rule: every ``*.yml`` / ``*.yaml`` data file under ``src/reporails_cli/``
must sit inside ``bundled/``. A lexical table, rule table, or config datum
burned into a subsystem package (``core/...``) is the regression this catches.

Run via ``poe arch`` alongside ``lint-imports``.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "reporails_cli"
BUNDLED = SRC / "bundled"
DATA_SUFFIXES = (".yml", ".yaml")


def find_stray_data() -> list[Path]:
    """Return data files under ``src/reporails_cli/`` that live outside ``bundled/``."""
    stray: list[Path] = []
    for path in SRC.rglob("*"):
        if path.suffix not in DATA_SUFFIXES:
            continue
        if "__pycache__" in path.parts:
            continue
        if BUNDLED in path.parents:
            continue
        stray.append(path)
    return sorted(stray)


def main() -> int:
    stray = find_stray_data()
    if not stray:
        print("bundled_data_gate: OK — all lexical/rule data under bundled/.")
        return 0
    print("bundled_data_gate: data files outside bundled/ (burn them into bundled/ instead):")
    for path in stray:
        print(f"  {path.relative_to(REPO_ROOT)}")
    print("\nFAIL: lexical/rule data must live under src/reporails_cli/bundled/.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
