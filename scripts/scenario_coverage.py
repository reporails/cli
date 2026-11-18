#!/usr/bin/env python3
"""Map each upper-tier behave scenario to the `src/reporails_cli` lines it executes.

    uv run python scripts/scenario_coverage.py build --out <map.json> [--tags=-api] [--workers N]

Every scenario runs on its own (`behave <feature>:<line>`) under coverage. The `ails` and
`reporails-mcp` processes the steps launch are measured through coverage's subprocess support: the
venv's coverage `.pth` hook starts measurement in each child when `COVERAGE_PROCESS_START` names an
rcfile, and the rcfile's `patch = subprocess, _exit, fork` also measures the forked mapper daemon
(which leaves through `os._exit`). The map is `{ "<relpath>": { "<line>": ["<feature>:<line>", ...] } }`
and feeds `mutation_probe.py --scenarios-from`: a scenario that never executes a mutated line cannot
kill that mutant.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ROOT / "tests" / "behave"
SOURCE = ROOT / "src" / "reporails_cli"
VENV_BIN = Path(sys.executable).parent
_SCENARIO_TIMEOUT_S = 900


def scenario_ids(tags: str | None) -> list[str]:
    """Every runnable scenario (an outline example counts once) as `<feature relpath>:<line>`."""
    from behave.parser import parse_file
    from behave.tag_expression import make_tag_expression

    expression = make_tag_expression([tags[len("--tags=") :]]) if tags else None
    ids: list[str] = []
    for path in sorted(FEATURES.glob("*.feature")):
        feature = parse_file(str(path))
        rel = path.relative_to(ROOT).as_posix()
        ids.extend(
            f"{rel}:{scenario.line}"
            for scenario in feature.walk_scenarios()
            if expression is None or expression.check([str(t) for t in scenario.effective_tags])
        )
    return ids


def _rcfile(work: Path) -> Path:
    rc = work / "coveragerc"
    rc.write_text(
        f"[run]\nparallel = True\nsource = {SOURCE}\npatch = subprocess, _exit, fork\n",
        encoding="utf-8",
    )
    return rc


def run_scenario(scenario: str, rc: Path, work: Path, tags: str | None) -> tuple[dict[str, list[int]], int]:
    """Run one scenario under coverage; (file relpath -> executed lines, behave exit code)."""
    data_dir = Path(tempfile.mkdtemp(prefix="sc-", dir=work))
    env = {
        **os.environ,
        "PATH": f"{VENV_BIN}{os.pathsep}{os.environ.get('PATH', '')}",
        "COVERAGE_PROCESS_START": str(rc),
        "COVERAGE_FILE": str(data_dir / ".coverage"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.pop("VIRTUAL_ENV", None)
    cmd = [str(VENV_BIN / "behave"), "-f", "null"]
    if tags:
        cmd.append(tags)
    cmd.append(scenario)
    try:
        code = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, timeout=_SCENARIO_TIMEOUT_S).returncode
    except subprocess.TimeoutExpired:
        code = -1
    return _combine(data_dir, rc), code


def _combine(data_dir: Path, rc: Path) -> dict[str, list[int]]:
    from coverage import Coverage

    cov = Coverage(data_file=str(data_dir / ".coverage"), config_file=str(rc))
    try:
        cov.combine(data_paths=[str(data_dir)], strict=False, keep=False)
    except Exception:  # pylint: disable=broad-exception-caught  # no data files: scenario recorded nothing
        return {}
    data = cov.get_data()
    out: dict[str, list[int]] = {}
    for file in data.measured_files():
        path = Path(file)
        if path.is_relative_to(SOURCE):
            out[path.relative_to(ROOT).as_posix()] = sorted(data.lines(file) or [])
    shutil.rmtree(data_dir, ignore_errors=True)
    return out


def build(out: Path, tags: str | None, workers: int) -> int:
    scenarios = scenario_ids(tags)
    work = Path(tempfile.mkdtemp(prefix="scenario-coverage-"))
    rc = _rcfile(work)
    mapping: dict[str, dict[str, list[str]]] = {}
    failed: list[str] = []
    started = time.monotonic()
    print(f"{len(scenarios)} scenarios, {workers} workers", flush=True)

    def one(scenario: str) -> tuple[str, dict[str, list[int]], int]:
        lines, code = run_scenario(scenario, rc, work, tags)
        return scenario, lines, code

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for done, (scenario, lines, code) in enumerate(pool.map(one, scenarios), 1):
                if code != 0:
                    failed.append(f"{scenario} (exit {code})")
                for rel, executed in lines.items():
                    per_line = mapping.setdefault(rel, {})
                    for line in executed:
                        per_line.setdefault(str(line), []).append(scenario)
                if done % 10 == 0 or done == len(scenarios):
                    print(f"  {done}/{len(scenarios)} {time.monotonic() - started:.0f}s", flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out.write_text(json.dumps(mapping, sort_keys=True), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(mapping)} files) in {time.monotonic() - started:.0f}s")
    for item in failed:
        print(f"WARNING scenario not green under coverage: {item}", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build the scenario -> line map")
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--tags", help="behave tag filter, e.g. --tags=-api")
    b.add_argument("--workers", type=int, default=4)
    args, extra = parser.parse_known_args()
    tags = args.tags or next((e for e in extra if e.startswith("--tags=")), None)
    if tags and not tags.startswith("--tags="):
        tags = f"--tags={tags}"
    return build(args.out, tags, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
