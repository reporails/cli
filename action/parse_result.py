#!/usr/bin/env python3
"""Parse CombinedResult JSON and emit shell variables for GitHub Actions.

Usage: echo '<json>' | python3 parse_result.py
Outputs: _SCORE=X.X  _LEVEL=LN  _VIOLATIONS=N  (one per line, eval-safe)
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    d = json.load(sys.stdin)
    files = d.get("files", {})
    stats = d.get("stats", {})

    n_findings = sum(f.get("count", 0) for f in files.values())
    errors = stats.get("errors", 0)
    warnings = stats.get("warnings", 0)
    total = errors + warnings + stats.get("infos", 0)

    if total == 0:
        score = 10.0
    else:
        base = 6.0
        denom = max(total, 1)
        ep = min(4.0, errors / denom * 30)
        wp = min(2.0, warnings / denom * 2)
        score = max(0.0, min(10.0, base - ep - wp))

    score = round(score, 1)
    level = "L0" if not files else "L1"

    print(f"_SCORE={score}")
    print(f"_LEVEL={level}")
    print(f"_VIOLATIONS={n_findings}")


if __name__ == "__main__":
    main()
