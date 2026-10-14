#!/usr/bin/env python3
"""pylint gate for ``src/reporails_cli/``.

Runs pylint with the project configuration and fails on any message, so
``poe pylint_struct`` keeps the source at zero findings. It also polices the
escape hatch:

- a ``# pylint: disable=`` of a complexity check is forbidden outright — the code
  shrinks to fit the limit instead;
- any other ``# pylint: disable=`` must say why on the same line, as a trailing
  ``# <reason>`` comment after the disabled names.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "reporails_cli"

# pylint complexity codes and their named forms; a `# pylint: disable=` naming any
# of them is a forbidden suppression of the structural floor.
FORBIDDEN_DISABLE_TOKENS = (
    "too-many-instance-attributes",
    "too-many-public-methods",
    "too-many-return-statements",
    "too-many-branches",
    "too-many-arguments",
    "too-many-positional-arguments",
    "too-many-locals",
    "too-many-statements",
    "too-many-boolean-expressions",
    "too-many-nested-blocks",
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
    "R0917",
    "R1702",
    "C0301",
    "C0302",
)

_MESSAGE_RE = re.compile(r"^.+:\d+:\d+: [CRWEF]\d{4}:")
_DUPLICATE_RE = re.compile(r"^.+:\d+:\d+: R0801:")
_DISABLE_RE = re.compile(r"#\s*pylint:\s*disable(?:-next)?\s*=\s*([^#\n]+)(#\s*\S.*)?$", re.IGNORECASE)


def run_pylint() -> tuple[list[str], int]:
    """Every pylint message line for the source tree (duplicate-code blocks included), and pylint's exit status."""
    proc = subprocess.run(
        [sys.executable, "-m", "pylint", str(SRC), "--score=no"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    lines = proc.stdout.splitlines()
    messages: list[str] = []
    for i, line in enumerate(lines):
        if not _MESSAGE_RE.match(line):
            continue
        messages.append(line)
        if _DUPLICATE_RE.match(line):
            # A duplicate-code message names its two sites on the `==module:[a:b]` lines that follow.
            messages.extend(f"    {site}" for site in lines[i + 1 : i + 3] if site.startswith("=="))
    return messages, proc.returncode


def find_bad_disables() -> tuple[list[str], list[str]]:
    """`(forbidden, unexplained)`: complexity suppressions, and other suppressions with no reason."""
    forbidden: list[str] = []
    unexplained: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = _DISABLE_RE.search(line)
            if not match:
                continue
            site = f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}"
            disabled = match.group(1).lower()
            if any(token.lower() in disabled for token in FORBIDDEN_DISABLE_TOKENS):
                forbidden.append(site)
            elif not match.group(2):
                unexplained.append(site)
    return forbidden, unexplained


def main() -> int:
    """Print every finding; exit 1 when pylint reports anything or a suppression breaks the rules."""
    forbidden, unexplained = find_bad_disables()
    messages, status = run_pylint()

    for line in messages:
        print(line)
    if forbidden:
        print("\nFORBIDDEN complexity suppressions (restructure the code instead):")
        for site in forbidden:
            print(f"  {site}")
    if unexplained:
        print("\nSuppressions without a reason (add `# <why>` after the disabled names):")
        for site in unexplained:
            print(f"  {site}")

    count = sum(1 for line in messages if _MESSAGE_RE.match(line))
    print(f"\npylint: {count} message(s), {len(forbidden)} forbidden and {len(unexplained)} unexplained suppression(s)")
    # pylint's exit status is a bit mask: 1 = fatal, 32 = usage error; any set bit without a parsed
    # message means pylint did not report normally, so the run proves nothing.
    if status & (1 | 32) or (status and not count):
        print(f"FAIL: pylint exited with status {status} without a normal report.")
        return 1
    return 1 if count or forbidden or unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
