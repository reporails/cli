#!/usr/bin/env python3
"""Structural-complexity gate for ``src/reporails_cli/``.

Runs pylint's complexity checks and fails when the violation count rises above
the recorded baseline, turning ``poe pylint_struct`` into a real gate instead of
a ``--exit-zero`` advisory. Also polices the escape hatch: any ``# pylint:
disable=`` of a complexity check is forbidden, so the gate fails when one reappears.

Baseline lives in ``scripts/pylint_struct_baseline.txt`` (one integer). Lower it
whenever a slice reduces the count; the gate refuses a rising count and nudges
when the count drops below the baseline so the number never goes stale.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "reporails_cli"
BASELINE_FILE = Path(__file__).resolve().parent / "pylint_struct_baseline.txt"

# The complexity checks the gate enforces. Kept in sync with the poe invocation
# and with the forbidden-suppression list.
ENABLED_CHECKS = "R0902,R0904,R0911,R0912,R0913,R0914,R0915,R0916,C0301,C0302"

# pylint complexity codes + their named forms — any of these appearing in a
# `# pylint: disable=` comment is a forbidden suppression of the structural floor.
FORBIDDEN_DISABLE_TOKENS = (
    "too-many-instance-attributes",
    "too-many-public-methods",
    "too-many-return-statements",
    "too-many-branches",
    "too-many-arguments",
    "too-many-locals",
    "too-many-statements",
    "too-many-boolean-expressions",
    "line-too-long",
    "too-many-lines",
    "R0902",
    "R0904",
    "R0911",
    "R0912",
    "R0913",
    "R0914",
    "R0915",
    "R0916",
    "C0301",
    "C0302",
)

_VIOLATION_RE = re.compile(r"^.+:\d+:\d+: [RC]\d{4}:")
_DISABLE_RE = re.compile(r"#\s*pylint:\s*disable=([^#\n]+)")


def run_pylint() -> list[str]:
    """Return the pylint violation lines for the enabled complexity checks."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pylint",
            str(SRC),
            "--disable=all",
            f"--enable={ENABLED_CHECKS}",
            "--score=no",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    return [line for line in proc.stdout.splitlines() if _VIOLATION_RE.match(line)]


def find_forbidden_disables() -> list[str]:
    """Return `path:lineno` sites that suppress a complexity check via pylint disable."""
    hits: list[str] = []
    for path in SRC.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = _DISABLE_RE.search(line)
            if not match:
                continue
            disabled = match.group(1)
            if any(token in disabled for token in FORBIDDEN_DISABLE_TOKENS):
                rel = path.relative_to(REPO_ROOT)
                hits.append(f"{rel}:{lineno}: {line.strip()}")
    return hits


def read_baseline() -> int:
    return int(BASELINE_FILE.read_text(encoding="utf-8").strip())


def main() -> int:
    forbidden = find_forbidden_disables()
    violations = run_pylint()
    count = len(violations)
    baseline = read_baseline()

    if forbidden:
        print("FORBIDDEN complexity suppressions (not allowed):")
        for hit in forbidden:
            print(f"  {hit}")

    for line in violations:
        print(line)

    print(f"\npylint_struct: {count} structural violation(s); baseline {baseline}")

    if forbidden:
        print("FAIL: remove the # pylint: disable= complexity suppressions above.")
        return 1
    if count > baseline:
        print(f"FAIL: violation count rose ({baseline} -> {count}). Reduce complexity, do not suppress.")
        return 1
    if count < baseline:
        print(f"OK, but tighten the ratchet: lower {BASELINE_FILE.name} to {count}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
