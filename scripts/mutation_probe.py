#!/usr/bin/env python3
"""Bounded mutation probe — measures whether a test suite CATCHES real bugs.

For each mutable OPERATOR TOKEN in a source module, apply one mutation, run the
target pytest path, and record CAUGHT (suite went red — the mutant was killed) or
SURVIVED (suite stayed green — the bug would ship). The kill-rate is the honest
measure of the suite's power: a test earns its place by killing mutants, not by
asserting shape.

    uv run python scripts/mutation_probe.py <src.py> <pytest_target> [max_mutants]
    uv run python scripts/mutation_probe.py <src.py> --cmd "<killing command>" [max_mutants] [--timeout S]
        [--scenarios-from <map.json>] [--json <out.json>] [--confirm-kills N] [--validation-stamp <file>]

`--cmd` replaces the pytest target with an upper-tier killing command (e.g.
`uv run behave tests/behave --tags=@offline --stop`): exit 0 = the mutant SURVIVED, any other
exit = CAUGHT. The command runs once on the unmutated source first and must exit 0, so a
broken command is never read as a 100% kill-rate. The run drives the installed `ails` binary,
so the mutated module must be the one that binary imports (an editable install of this tree).

`--scenarios-from <map.json>` (with `--cmd`, a map built by `scripts/scenario_coverage.py build`) runs
each mutant against only the scenarios that execute the mutated statement: the command's feature-path
arguments are replaced by `feature:line` ids. A scenario that never runs the mutated line cannot kill the
mutant, so the verdict is the full run's. A mutant no scenario reaches is SURVIVED without running and
counted as `uncovered`. The unmutated validation run stays the full command. `--json <out>` writes one
`{line, col, original, replacement, verdict}` record per mutant, for tier-to-tier comparison.

`--confirm-kills N` (a flaky-suite guard): a mutant whose run fails is re-run up to N more times on
the mutant, and once on the UNMUTATED source. It counts CAUGHT only when every re-run also fails and the
unmutated run is green; a pass on any of them makes it FLAKY, reported apart (counted neither caught nor
survived, listed by line:col, `"verdict": "flaky"` in `--json`). A timeout keeps its meaning.
`--validation-stamp <file>` (with `--cmd`) skips the unmutated validation run when the stamp written by an
earlier green validation matches the current git HEAD, the same command, and a tree with no changes outside
the probed module; otherwise it validates and rewrites the stamp. The probe prints which happened.

Accuracy contract (so the headline number stays honest):
  - Mutations apply at exact `tokenize` OPERATOR/keyword positions, never by line
    regex, so operators inside strings, f-strings, and comments are never touched.
  - A mutant that fails to `compile()` is SKIPPED (not counted), so a syntax break
    is never miscounted as "caught".
  - When there are more sites than the cap, sites are sampled EVENLY across the
    file, not truncated to the top.
  - A mutant that makes the suite HANG (e.g. a loop-termination operator flipped to
    a non-terminating condition) is bounded by a per-mutant timeout and counted as
    CAUGHT (the suite does not pass — CI would time out red), reported separately so
    the headline stays honest.
  - The source is restored after every mutant AND via `atexit` AND on SIGTERM/SIGINT,
    so a killed run (a hang cut short by an outer timeout) never leaves the module
    mutated on disk. `atexit` alone does NOT fire on SIGTERM — the signal handler is
    what makes a killed probe non-destructive.

Concurrency: the probe mutates the target module IN PLACE on disk while pytest runs.
Do NOT run two probes at once on modules linked by an import — if module A is imported
(directly or transitively) by a test file B's probe runs, B's on-disk mutation corrupts
A's verdicts and a SURVIVED is miscounted as CAUGHT. Sequence probes across import-linked
modules; a whole-suite sweep runs them one at a time.

This is a diagnostic instrument, not a gate — it names WHERE a suite fails to catch
bugs so the missing behavioral test can be added.
"""

from __future__ import annotations

import ast
import atexit
import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tokenize
from collections import Counter
from pathlib import Path
from typing import NamedTuple

# Per-mutant wall-clock ceiling. A mutant that makes the suite loop forever (the
# operator that terminates a `while` flipped to a never-true condition) would hang
# the probe indefinitely without this; the outer timeout cuts it and it counts CAUGHT.
_MUTANT_TIMEOUT_S = 120


def _pytest_cmd() -> list[str]:
    """The per-mutant pytest invocation — fast direct venv runner when available.

    The suite is re-run once per mutant, so the invocation's own startup cost is
    multiplied by the site count. `uv run pytest` re-resolves the environment on
    every call (seconds each); the project venv's `pytest` skips that. Prefer the
    venv binary when it exists (a sweep of a whole module then runs in seconds, not
    minutes), fall back to `uv run pytest` for a fresh clone with no synced venv.
    Override with `MUTATION_PROBE_PYTEST` (space-separated) when neither fits.
    """
    override = os.environ.get("MUTATION_PROBE_PYTEST")
    if override:
        return override.split()
    venv_pytest = Path(".venv/bin/pytest")
    if venv_pytest.exists():
        return [str(venv_pytest)]
    return ["uv", "run", "pytest"]


_Site = tuple[int, int, int, str, str]  # (row, col_start, col_end, old, new)

# Exact-string swaps at OPERATOR / keyword token positions — each a plausible bug.
SWAPS: dict[str, str] = {
    ">=": ">",
    "<=": "<",
    "==": "!=",
    "!=": "==",
    "and": "or",
    "or": "and",
    "True": "False",
    "False": "True",
    "is": "is not",
}


def mutation_sites(source: str) -> list[_Site]:
    """(row, col_start, col_end, old, new) for every mutable operator token."""
    sites: list[_Site] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type in (tokenize.OP, tokenize.NAME) and tok.string in SWAPS:
                (r, c0), (_, c1) = tok.start, tok.end
                sites.append((r, c0, c1, tok.string, SWAPS[tok.string]))
    except tokenize.TokenError:
        pass
    return sites


def _sample(sites: list[_Site], cap: int) -> list[_Site]:
    """Even stride sample across the whole file, never a top-of-file truncation."""
    if cap <= 0:
        return []  # a non-positive cap probes nothing; never divide by zero below
    if len(sites) <= cap:
        return sites
    stride = len(sites) / cap
    return [sites[int(i * stride)] for i in range(cap)]


# pytest's own exit codes for "the invocation itself is broken" — never a mutant verdict.
# 4 = usage error (e.g. a target path that does not exist); 5 = no tests were collected.
# See https://docs.pytest.org/en/stable/reference/exit-codes.html
_PYTEST_USAGE_ERROR = 4
_PYTEST_NO_TESTS_COLLECTED = 5
_PYTEST_INVOCATION_BROKEN = {_PYTEST_USAGE_ERROR, _PYTEST_NO_TESTS_COLLECTED}


def run_tests(target: str, timeout: int = _MUTANT_TIMEOUT_S) -> str:
    """Run the suite against the on-disk mutant.

    Returns one of: "survived" (suite PASSED — the bug would ship), "caught"
    (suite FAILED — a test reddened), "hang" (the mutant made the suite exceed
    the per-mutant timeout, e.g. a flipped loop-terminator — the suite did not pass,
    so CI would time out red; counted with the caught mutants but reported apart), or
    "error" (pytest exit 4/5 — the TARGET itself is broken, e.g. a typo'd or renamed
    path, not the mutant; never counted as a kill, or a mistyped target would report a
    fabricated 100% kill-rate against tests that never ran).

    `PYTHONDONTWRITEBYTECODE=1` is forced in the child env: mutants are written and
    reverted in rapid succession, often leaving the file's size and mtime-second
    unchanged, so a stale `__pycache__/*.pyc` can shadow the mutated source and make
    the mutation silently NOT take — which reads as a FALSE SURVIVOR (never a false
    caught). Disabling bytecode caching forces the interpreter to recompile the live
    source every run, so the verdict reflects the mutant actually on disk.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(
            [*_pytest_cmd(), *target.split(), "-q", "-x", "--no-header", "-p", "no:cacheprovider"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "hang"
    if r.returncode in _PYTEST_INVOCATION_BROKEN:
        return "error"
    return "survived" if r.returncode == 0 else "caught"


_WINDOWS = os.name == "nt"


def _command_args(command: str) -> str | list[str]:
    """What `subprocess.run` takes for `command`: the string itself on Windows (the child parses it), argv elsewhere."""
    return command if _WINDOWS else shlex.split(command)


def _split_command(command: str) -> list[str]:
    """Split a command string into argv the way the platform's runtime parses it."""
    if not _WINDOWS:
        return shlex.split(command)
    import ctypes  # pylint: disable=import-outside-toplevel  # Windows-only branch
    from ctypes import wintypes  # pylint: disable=import-outside-toplevel  # Windows-only branch

    shell32 = ctypes.windll.shell32  # type: ignore[attr-defined,unused-ignore]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    argv = shell32.CommandLineToArgvW(command, ctypes.byref(count))
    if not argv:
        raise ValueError(f"cannot split command {command!r}")
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        kernel32.LocalFree(argv)


def _join_command(argv: list[str]) -> str:
    """Join argv into a command string that `_split_command` reads back as the same argv."""
    return subprocess.list2cmdline(argv) if _WINDOWS else shlex.join(argv)


def run_command(command: str, timeout: int) -> str:
    """Run an upper-tier killing command against the on-disk mutant.

    Returns "survived" (exit 0), "caught" (any other exit) or "hang" (over `timeout` seconds,
    counted with the caught mutants like a pytest hang). `PYTHONDONTWRITEBYTECODE=1` is forced
    for the same stale-bytecode reason as `run_tests`.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(_command_args(command), capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "hang"
    return "survived" if r.returncode == 0 else "caught"


def _statement_lines(source: str, row: int) -> range:
    """Every line of the innermost statement holding `row` (a compound statement: its header only).

    Coverage records the line events of a statement, which on a multi-line statement need not be
    the line the operator sits on, so the scoped run unions the whole statement's lines.
    """
    best = range(row, row + 1)
    best_size: int | None = None
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.stmt):
            continue
        end = node.end_lineno or node.lineno
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            end = body[0].lineno - 1
        if node.lineno <= row <= end and (best_size is None or end - node.lineno < best_size):
            best, best_size = range(node.lineno, end + 1), end - node.lineno
    return best


def _scenarios_for(coverage: dict[str, list[str]], lines: range) -> list[str]:
    """The scenario ids covering any of `lines`, in a stable order."""
    ids: set[str] = set()
    for line in lines:
        ids.update(coverage.get(str(line), ()))
    return sorted(ids)


def _scoped_command(command: str, scenarios: list[str]) -> str:
    """`command` with its feature-path arguments replaced by the `feature:line` scenario ids."""
    kept = [
        t
        for t in _split_command(command)
        if t.startswith("-") or not (".feature" in t or "tests/behave" in t.replace("\\", "/"))
    ]
    return _join_command([*kept, *scenarios])


def _validate_command(command: str, timeout: int) -> str | None:
    """Run the killing command once on the unmutated source; an error message unless it exits 0.

    A command that cannot start, or is red before any mutant, would read every mutant as
    caught: refuse it before a mutant is written.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(_command_args(command), capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"killing command {command!r} did not complete on the unmutated source: {exc}"
    if r.returncode != 0:
        tail = (r.stdout + r.stderr)[-2000:]
        return f"killing command {command!r} exits {r.returncode} on the unmutated source:\n{tail}"
    return None


def _validate_target(target: str) -> str | None:
    """Run a quick collect-only pass to catch a broken target BEFORE any mutant is written.

    Returns an error message on failure (usage error / no tests collected), None when the
    target collects cleanly. Without this, a typo'd or renamed target would silently report a
    100% kill-rate — every mutant's `run_tests` call fails the same way `run_tests` would on a
    clean baseline, which `run_tests` alone cannot distinguish from a fluke on one mutant.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run(
        [*_pytest_cmd(), *target.split(), "--collect-only", "-q"],
        capture_output=True,
        text=True,
        env=env,
    )
    if r.returncode in _PYTEST_INVOCATION_BROKEN:
        return (r.stdout + r.stderr).strip() or f"pytest exited {r.returncode} collecting {target!r}"
    return None


def _option(argv: list[str], flag: str) -> tuple[list[str], str | None]:
    """`argv` without `flag <value>`, and that value (None when the flag is absent)."""
    if flag not in argv:
        return argv, None
    i = argv.index(flag)
    if i + 1 >= len(argv):
        raise SystemExit(f"{flag} needs a value")
    return argv[:i] + argv[i + 2 :], argv[i + 1]


class _Args(NamedTuple):
    src: Path
    target: str  # the pytest target; "" when a killing command is given
    command: str | None
    cap: int
    timeout: int
    scenarios_from: Path | None = None
    json_out: Path | None = None
    confirm_kills: int = 0
    stamp: Path | None = None


def _parse_args(raw: list[str]) -> _Args | None:
    """The probe's arguments, or None when they do not name a module and a killer."""
    argv, command = _option(raw, "--cmd")
    argv, timeout_text = _option(argv, "--timeout")
    argv, map_text = _option(argv, "--scenarios-from")
    argv, json_text = _option(argv, "--json")
    argv, confirm_text = _option(argv, "--confirm-kills")
    argv, stamp_text = _option(argv, "--validation-stamp")
    confirm = int(confirm_text) if confirm_text is not None else 0
    stamp = Path(stamp_text) if stamp_text is not None else None
    scenarios_from = Path(map_text) if map_text is not None else None
    json_out = Path(json_text) if json_text is not None else None
    timeout = int(timeout_text) if timeout_text is not None else _MUTANT_TIMEOUT_S
    if not argv or (command is None and len(argv) < 2):
        return None
    if scenarios_from is not None and command is None:
        raise SystemExit("--scenarios-from needs --cmd")
    if stamp is not None and command is None:
        raise SystemExit("--validation-stamp needs --cmd")
    extra = (scenarios_from, json_out, confirm, stamp)
    if command is not None:
        return _Args(Path(argv[0]), "", command, int(argv[1]) if len(argv) > 1 else 60, timeout, *extra)
    return _Args(Path(argv[0]), argv[1], None, int(argv[2]) if len(argv) > 2 else 60, timeout, *extra)


def _baseline_error(args: _Args) -> str | None:
    """Why the killer cannot give a verdict on the unmutated source, or None when it can."""
    if args.command is None:
        error = _validate_target(args.target)
        return (
            None if error is None else f"pytest cannot collect target {args.target!r} — not a mutant verdict:\n{error}"
        )
    error = _validate_command(args.command, args.timeout)
    return None if error is None else f"the killing command is not a green baseline — not a mutant verdict:\n{error}"


def _git(*git_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *git_args], capture_output=True, text=True, check=False)


def _stamp_state(command: str, module: Path) -> dict[str, object]:
    """The stamp body: git HEAD, the command, and whether the tree is clean outside `module`."""
    head = _git("rev-parse", "HEAD").stdout.strip()
    rel = str(module.resolve().relative_to(Path.cwd().resolve()))
    clean = _git("diff", "--quiet", "HEAD", "--", ".", f":(exclude){rel}").returncode == 0
    return {"head": head, "command": command, "clean": clean}


def _stamp_matches(stamp: Path, command: str, module: Path) -> bool:
    """True when an earlier green validation covers this HEAD, command and tree (outside `module`)."""
    try:
        saved = json.loads(stamp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    now = _stamp_state(command, module)
    return (
        bool(saved.get("clean"))
        and bool(now["clean"])
        and saved.get("head") == now["head"]
        and (saved.get("command") == command and bool(now["head"]))
    )


def _validate_baseline(args: _Args) -> str | None:
    """`_baseline_error`, except a matching `--validation-stamp` skips the run; prints which happened."""
    if args.stamp is None or args.command is None:
        return _baseline_error(args)
    if _stamp_matches(args.stamp, args.command, args.src):
        print(f"validation: SKIPPED (stamp {args.stamp} matches HEAD, command and tree)", flush=True)
        return None
    error = _baseline_error(args)
    if error is None:
        args.stamp.write_text(json.dumps(_stamp_state(args.command, args.src)), encoding="utf-8")
        print(f"validation: RAN green, stamp {args.stamp} written", flush=True)
    return error


def _record(row: int, col: int, old: str, new: str, verdict: str, *, uncovered: bool = False) -> dict[str, object]:
    """One mutant's JSON record."""
    rec: dict[str, object] = {"line": row, "col": col, "original": old, "replacement": new, "verdict": verdict}
    if uncovered:
        rec["uncovered"] = True
    return rec


def _load_coverage(args: _Args) -> dict[str, list[str]]:
    """The scenario map's entry for the probed module ({} without `--scenarios-from`)."""
    if args.scenarios_from is None:
        return {}
    key = str(args.src.resolve().relative_to(Path.cwd().resolve()))
    return dict(json.loads(args.scenarios_from.read_text(encoding="utf-8")).get(key, {}))


def _mutant_verdict(
    args: _Args, original: str, source: str, row: int, coverage: dict[str, list[str]]
) -> tuple[str, bool]:
    """(verdict, uncovered) for one mutant: run it, or with a scenario map run only the covering scenarios.

    The on-disk module is restored to `original` before returning.
    """
    command = args.command
    if args.scenarios_from is not None and command is not None:
        scoped = _scenarios_for(coverage, _statement_lines(original, row))
        if not scoped:
            return "survived", True  # no scenario executes this statement: it cannot be killed
        command = _scoped_command(command, scoped)

    def run() -> str:
        return run_tests(args.target, args.timeout) if command is None else run_command(command, args.timeout)

    args.src.write_text(source)
    try:
        verdict = run()
        for _ in range(args.confirm_kills if verdict == "caught" else 0):
            if run() == "survived":
                verdict = "flaky"  # the mutant passed on a re-run: the kill is not reproducible
                break
    finally:
        args.src.write_text(original)
    if verdict == "caught" and args.confirm_kills > 0 and run() != "survived":
        verdict = "flaky"  # the scenario set is not green on the unmutated source
    return verdict, False


def _report(args: _Args, records: list[dict[str, object]], survivors: list[str]) -> None:
    """Print the kill-rate summary, the flaky mutants and the survivors."""
    tally = Counter(str(r["verdict"]) for r in records)
    uncovered = sum(1 for r in records if r.get("uncovered"))
    killed = tally["caught"] + tally["hang"]
    total = killed + tally["survived"]
    rate = f"{killed}/{total}" if total else "0/0"
    hung_note = f", {tally['hang']} via-timeout" if tally["hang"] else ""
    flaky_note = f", {tally['flaky']} flaky (excluded)" if tally["flaky"] else ""
    error_note = f", {tally['error']} pytest-errors (excluded)" if tally["error"] else ""
    if args.scenarios_from is not None:
        print(f"scoped run: {uncovered} uncovered mutants SURVIVED without running (no scenario executes the line)")
    print(
        f"\nKILL-RATE: {rate} caught{hung_note}  "
        f"({tally['survived']} survived, {tally['invalid']} invalid-skipped{flaky_note}{error_note})",
        flush=True,
    )
    flaky_sites = [f"{r['line']}:{r['col']}" for r in records if r["verdict"] == "flaky"]
    if flaky_sites:
        print(f"FLAKY (a re-run disagreed; counted neither caught nor survived; line:col): {', '.join(flaky_sites)}")
    if survivors:
        print("SURVIVORS (uncaught real mutations — add a test that reddens on each):")
        print("\n".join(survivors[:30]), flush=True)


def main() -> int:
    args = _parse_args(sys.argv[1:])
    if args is None:
        print(__doc__)
        return 2
    src, cap, timeout = args.src, args.cap, args.timeout

    # Fail fast BEFORE any mutant is written — a typo'd or renamed pytest target (or a killing
    # command that is red or will not start) must never be misread as a clean 100% kill-rate.
    baseline_error = _validate_baseline(args)
    if baseline_error is not None:
        print(f"ERROR: {baseline_error}", file=sys.stderr)
        return 1

    original = src.read_text()

    # Restore on EVERY exit path: after each mutant (the `finally` below), on a clean
    # or exception exit (`atexit`), AND on SIGTERM/SIGINT. The signal handler is the
    # one that matters when an outer timeout kills a hung run — `atexit` does NOT fire
    # on SIGTERM, so without this a killed probe leaves the module mutated on disk.
    def _restore(*_: object) -> None:
        src.write_text(original)

    def _terminate(*_: object) -> None:
        _restore()
        sys.exit(130)

    atexit.register(_restore)
    for _sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(_sig, _terminate)

    lines = original.splitlines(keepends=True)
    sites = _sample(mutation_sites(original), cap)

    coverage = _load_coverage(args)

    records: list[dict[str, object]] = []
    survivors: list[str] = []
    print(f"module={src.name} sites={len(sites)} timeout={timeout}s/mutant", flush=True)

    try:
        for row, c0, c1, old, new in sites:
            line = lines[row - 1]
            trial = lines.copy()
            trial[row - 1] = line[:c0] + new + line[c1:]
            source = "".join(trial)
            try:
                compile(source, str(src), "exec")
            except SyntaxError:
                records.append(_record(row, c0, old, new, "invalid"))  # never miscount as caught
                continue
            verdict, is_uncovered = _mutant_verdict(args, original, source, row, coverage)
            records.append(_record(row, c0, old, new, verdict, uncovered=is_uncovered))
            if verdict == "survived":
                survivors.append(f"  L{row}: {line.strip()[:66]}  [{old} -> {new}] SURVIVED")
    finally:
        _restore()

    if args.json_out is not None:
        args.json_out.write_text(json.dumps(records, indent=1), encoding="utf-8")
    _report(args, records, survivors)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
