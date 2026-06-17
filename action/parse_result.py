#!/usr/bin/env python3
"""Parse CombinedResult JSON and emit shell variables for GitHub Actions.

Usage: echo '<json>' | python3 parse_result.py
Outputs: _SCORE=X.X  _LEVEL=LN  _VIOLATIONS=N  (one per line, eval-safe)

_SCORE is the analysis service's whole-project Quality verdict (the same number
`ails check` prints), read verbatim from the `quality` key — never recomputed here.
It is empty when no server score is available (offline run); the min-score gate
treats an empty score as "skip".
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    d = json.load(sys.stdin)
    files = d.get("files", {})
    stats = d.get("stats", {})

    quality = d.get("quality")  # float, or None when offline / no server score
    level = d.get("level", "L0")
    violations = stats.get("total_findings", sum(f.get("count", 0) for f in files.values()))

    score_out = "" if quality is None else f"{float(quality):.1f}"

    print(f"_SCORE={score_out}")
    print(f"_LEVEL={level}")
    print(f"_VIOLATIONS={violations}")


if __name__ == "__main__":
    main()
