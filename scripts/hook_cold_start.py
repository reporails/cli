"""Maintainer script: cold-start timing of `ails hook`.

Usage: uv run python scripts/hook_cold_start.py PAYLOADS_FILE N

Runs the venv's `ails hook --agent claude` once per payload (the file's lines, cycled to reach N),
each a fresh process, under a throwaway HOME, and prints p50 / p95 / max in milliseconds.
"""

from __future__ import annotations

import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main(argv: list[str]) -> int:
    """Time N cold hook runs over the payload file's lines."""
    if len(argv) != 3:
        print(__doc__)
        return 2
    lines = Path(argv[1]).read_text(encoding="utf-8").splitlines()
    count = int(argv[2])
    ails = shutil.which("ails")
    if ails is None or not lines:
        print("`ails` not on PATH or no payloads")
        return 2
    samples: list[float] = []
    with tempfile.TemporaryDirectory(prefix="ails-hook-cold-") as home:
        env = {**os.environ, "HOME": home, "USERPROFILE": home}
        for index in range(count):
            payload = lines[index % len(lines)].encode()
            start = time.perf_counter()
            done = subprocess.run([ails, "hook", "--agent", "claude"], input=payload, env=env, capture_output=True, check=False)
            samples.append((time.perf_counter() - start) * 1000)
            if done.returncode != 0 or done.stdout:
                print(f"run {index}: exit {done.returncode}, stdout {done.stdout!r}")
                return 1
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    print(f"n={count} p50={statistics.median(ordered):.0f} ms p95={p95:.0f} ms max={ordered[-1]:.0f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
