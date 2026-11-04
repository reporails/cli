"""Run the behave feature files in concurrent processes and print one summary.

Usage: uv run python scripts/behave_parallel.py [extra behave args, e.g. --tags=-api]

Each process runs its own subset of feature files with its own JUnit output; the
features are balanced longest-first from the previous run's JUnit times when present.
Exits non-zero when any process fails.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ROOT / "tests" / "behave"
JUNIT = ROOT / "tmp" / "behave-junit"
WORKERS = max(1, min(4, (os.cpu_count() or 2) // 2))


Unit = tuple[str, int, str]  # (feature file name, scenario line, scenario name)


def scenario_units(features: list[Path]) -> list[Unit]:
    """Every runnable scenario (an outline example counts once) as (file, line, name)."""
    from behave.parser import parse_file

    units: list[Unit] = []
    for path in features:
        feature = parse_file(str(path))
        units += [(path.name, scenario.line, scenario.name) for scenario in feature.walk_scenarios()]
    return units


def previous_times() -> dict[tuple[str, str], float]:
    """(feature stem, scenario name) -> seconds from the last run's JUnit files."""
    return {key: seconds for key, (seconds, _) in read_cases(sorted(JUNIT.glob("TESTS-*.xml"))).items()}


def balance(units: list[Unit], times: dict[tuple[str, str], float], workers: int) -> list[list[Unit]]:
    """Longest-first greedy over scenarios: each goes to the currently lightest bucket.

    A scenario with no recorded time weighs the mean of its feature's recorded ones, else 1 second.
    """
    by_feature: dict[str, list[float]] = {}
    for (stem, _), seconds in times.items():
        by_feature.setdefault(stem, []).append(seconds)

    def weight(unit: Unit) -> float:
        stem = Path(unit[0]).stem
        if (stem, unit[2]) in times:
            return times[(stem, unit[2])]
        known = by_feature.get(stem)
        return sum(known) / len(known) if known else 1.0

    buckets: list[list[Unit]] = [[] for _ in range(workers)]
    loads = [0.0] * workers
    for unit in sorted(units, key=lambda u: (-weight(u), u[0], u[1])):
        lightest = loads.index(min(loads))
        buckets[lightest].append(unit)
        loads[lightest] += weight(unit)
    return [sorted(b) for b in buckets if b]


def run_bucket(index: int, units: list[Unit], extra: list[str], out_dir: Path) -> subprocess.Popen[bytes]:
    worker_dir = out_dir / f"worker-{index}"
    worker_dir.mkdir()
    log = (out_dir / f"worker-{index}.log").open("wb")
    selectors = [f"{FEATURES / name}:{line}" for name, line, _ in units]
    cmd = [
        sys.executable,
        "-m",
        "behave",
        "-f",
        "progress",
        "--junit",
        "--junit-directory",
        str(worker_dir),
        "--no-color",
        *extra,
        *selectors,
    ]
    # Each `ails` the scenarios run gets its share of the cores, so concurrent processes do not oversubscribe them.
    env = {**os.environ, "BEHAVE_ENCODE_WORKERS": str(max(1, (os.cpu_count() or 2) // WORKERS))}
    return subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)


def stem_of(report: Path) -> str:
    """Feature stem of a JUnit report, whether it is a plain `TESTS-<stem>.xml` or a kept per-process piece."""
    name = report.stem.removeprefix("TESTS-")
    return name.split("-", 2)[2] if name.startswith("worker-") else name


def read_cases(reports: list[Path]) -> dict[tuple[str, str], tuple[float, str]]:
    """(feature stem, scenario name) -> (seconds, status), one entry per scenario across every report.

    A process that ran one slice of a feature still lists the rest as skipped; the entry from the
    process that ran the scenario wins.
    """
    cases: dict[tuple[str, str], tuple[float, str]] = {}
    for report in reports:
        try:
            root = ET.parse(report).getroot()
        except ET.ParseError:
            continue
        for case in root.iter("testcase"):
            status = case.get("status", "")
            key = (stem_of(report), case.get("name", ""))
            if key not in cases or status != "skipped":
                cases[key] = (float(case.get("time", 0)), status)
    return cases


def collect(out_dir: Path) -> tuple[list[tuple[str, str, float, int]], list[tuple[float, str, str]]]:
    """Per-feature (stem, status, seconds, scenarios) and every scenario's (seconds, feature, name)."""
    cases = read_cases(sorted(out_dir.glob("worker-*/TESTS-*.xml")))
    merged: dict[str, tuple[str, float, int]] = {}
    for (stem, _), (seconds, status) in cases.items():
        bad, total, count = merged.get(stem, ("ok", 0.0, 0))
        merged[stem] = ("FAIL" if bad == "FAIL" or status in ("failed", "error") else "ok", total + seconds, count + 1)
    rows = [(stem, bad, total, count) for stem, (bad, total, count) in merged.items()]
    return rows, [(seconds, stem, name) for (stem, name), (seconds, _) in cases.items()]


def hold_performance() -> None:
    """Re-run this script under the `performance` power profile when `powerprofilesctl` offers one.

    A laptop on its balanced profile caps the clock under multi-core load, which more than doubles the suite's
    wall time. `powerprofilesctl launch` holds the profile only while this run lives and restores the previous one
    when it ends. `BEHAVE_POWER=keep` leaves the profile alone.
    """
    if os.environ.get("BEHAVE_POWER") == "keep" or os.environ.get("BEHAVE_POWER_HELD"):
        return
    tool = shutil.which("powerprofilesctl")
    if tool is None:
        return
    listed = subprocess.run([tool, "list"], capture_output=True, text=True, check=False)
    if listed.returncode != 0 or "performance:" not in listed.stdout:
        return
    print("holding the performance power profile while the suite runs (BEHAVE_POWER=keep to skip)", flush=True)
    cmd = [tool, "launch", "-p", "performance", "-r", "behave suite", "--", sys.executable, __file__, *sys.argv[1:]]
    os.execvpe(tool, cmd, {**os.environ, "BEHAVE_POWER_HELD": "1"})


def main() -> int:
    hold_performance()
    extra = sys.argv[1:]
    units = scenario_units(sorted(FEATURES.glob("*.feature")))
    times = previous_times()
    work_dir = JUNIT.parent / "behave-junit-run"
    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)
    start = time.monotonic()
    buckets = balance(units, times, WORKERS)
    procs = [run_bucket(i, files, extra, work_dir) for i, files in enumerate(buckets)]
    codes = [p.wait() for p in procs]
    wall = time.monotonic() - start
    rows, scenarios = collect(work_dir)
    JUNIT.mkdir(parents=True, exist_ok=True)
    for stale in JUNIT.glob("*"):
        stale.unlink()
    for report in work_dir.glob("worker-*/TESTS-*.xml"):
        # A feature split over processes keeps one report per piece; the next run reads every scenario time
        # from them all.
        report.replace(JUNIT / f"TESTS-{report.parent.name}-{report.stem.removeprefix('TESTS-')}.xml")
    for i, code in enumerate(codes):
        if code:
            log = work_dir / f"worker-{i}.log"
            print(f"--- worker {i} failed (exit {code}); tail of {log} ---")
            print("\n".join(log.read_text(errors="replace").splitlines()[-40:]))
    print(f"\n{'feature':<22}{'status':<8}{'seconds':>8}{'scenarios':>11}")
    for stem, status, seconds, count in sorted(rows, key=lambda r: -r[2]):
        print(f"{stem:<22}{status:<8}{seconds:>8.1f}{count:>11}")
    print("\nslowest scenarios:")
    for seconds, stem, name in sorted(scenarios, reverse=True)[:10]:
        print(f"  {seconds:6.1f}s  {stem}: {name}")
    print(f"\n{len(scenarios)} scenarios in {len(rows)} features, {len(buckets)} processes, wall {wall:.1f}s")
    return 1 if any(codes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
