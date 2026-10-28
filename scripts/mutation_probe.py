#!/usr/bin/env python3
"""Bounded mutation probe — measures whether a test suite CATCHES real bugs.

For each mutable OPERATOR TOKEN in a source module, apply one mutation, run the
target pytest path, and record CAUGHT (suite went red — the mutant was killed) or
SURVIVED (suite stayed green — the bug would ship). The kill-rate is the honest
measure of the suite's power: a test earns its place by killing mutants, not by
asserting shape.

    uv run python scripts/mutation_probe.py <src.py> <pytest_target> [max_mutants]
    uv run python scripts/mutation_probe.py <src.py> --cmd "<killing command>" [max_mutants] [--timeout S]

`--cmd` replaces the pytest target with an upper-tier killing command (e.g.
`uv run behave tests/behave --tags=@offline --stop`): exit 0 = the mutant SURVIVED, any other
exit = CAUGHT. The command runs once on the unmutated source first and must exit 0, so a
broken command is never read as a 100% kill-rate. The run drives the installed `ails` binary,
so the mutated module must be the one that binary imports (an editable install of this tree).

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

import atexit
import io
import os
import shlex
import signal
import subprocess
import sys
import tokenize
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


def mutation_sites(source: str) -> list[tuple[int, int, int, str, str]]:
    """(row, col_start, col_end, old, new) for every mutable operator token."""
    sites: list[tuple[int, int, int, str, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type in (tokenize.OP, tokenize.NAME) and tok.string in SWAPS:
                (r, c0), (_, c1) = tok.start, tok.end
                sites.append((r, c0, c1, tok.string, SWAPS[tok.string]))
    except tokenize.TokenError:
        pass
    return sites


def _sample(sites: list, cap: int) -> list:
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


def run_tests(target: str) -> str:
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
            timeout=_MUTANT_TIMEOUT_S,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "hang"
    if r.returncode in _PYTEST_INVOCATION_BROKEN:
        return "error"
    return "survived" if r.returncode == 0 else "caught"


def run_command(command: str, timeout: int) -> str:
    """Run an upper-tier killing command against the on-disk mutant.

    Returns "survived" (exit 0), "caught" (any other exit) or "hang" (over `timeout` seconds,
    counted with the caught mutants like a pytest hang). `PYTHONDONTWRITEBYTECODE=1` is forced
    for the same stale-bytecode reason as `run_tests`.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "hang"
    return "survived" if r.returncode == 0 else "caught"


def _validate_command(command: str, timeout: int) -> str | None:
    """Run the killing command once on the unmutated source; an error message unless it exits 0.

    A command that cannot start, or is red before any mutant, would read every mutant as
    caught: refuse it before a mutant is written.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=timeout, env=env)
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


def _parse_args(raw: list[str]) -> _Args | None:
    """The probe's arguments, or None when they do not name a module and a killer."""
    argv, command = _option(raw, "--cmd")
    argv, timeout_text = _option(argv, "--timeout")
    timeout = int(timeout_text) if timeout_text is not None else _MUTANT_TIMEOUT_S
    if not argv or (command is None and len(argv) < 2):
        return None
    if command is not None:
        return _Args(Path(argv[0]), "", command, int(argv[1]) if len(argv) > 1 else 60, timeout)
    return _Args(Path(argv[0]), argv[1], None, int(argv[2]) if len(argv) > 2 else 60, timeout)


def _baseline_error(args: _Args) -> str | None:
    """Why the killer cannot give a verdict on the unmutated source, or None when it can."""
    if args.command is None:
        error = _validate_target(args.target)
        return (
            None if error is None else f"pytest cannot collect target {args.target!r} — not a mutant verdict:\n{error}"
        )
    error = _validate_command(args.command, args.timeout)
    return None if error is None else f"the killing command is not a green baseline — not a mutant verdict:\n{error}"


def main() -> int:
    args = _parse_args(sys.argv[1:])
    if args is None:
        print(__doc__)
        return 2
    src, target, command, cap, timeout = args

    # Fail fast BEFORE any mutant is written — a typo'd or renamed pytest target (or a killing
    # command that is red or will not start) must never be misread as a clean 100% kill-rate.
    baseline_error = _baseline_error(args)
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

    atexit.register(_restore)
    for _sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(_sig, lambda *_: (_restore(), sys.exit(130)))

    lines = original.splitlines(keepends=True)
    sites = _sample(mutation_sites(original), cap)

    caught = survived = skipped = hung = errors = 0
    survivors: list[str] = []
    print(f"module={src.name} sites={len(sites)} timeout={timeout}s/mutant", flush=True)

    try:
        for row, c0, c1, old, new in sites:
            line = lines[row - 1]
            mutated_line = line[:c0] + new + line[c1:]
            trial = lines.copy()
            trial[row - 1] = mutated_line
            source = "".join(trial)
            try:
                compile(source, str(src), "exec")
            except SyntaxError:
                skipped += 1  # invalid mutant — never miscount as caught
                continue
            src.write_text(source)
            try:
                verdict = run_tests(target) if command is None else run_command(command, timeout)
            finally:
                src.write_text(original)
            if verdict == "survived":
                survived += 1
                survivors.append(f"  L{row}: {line.strip()[:66]}  [{old} -> {new}] SURVIVED")
            elif verdict == "hang":
                hung += 1  # non-terminating mutant — caught, but flagged apart
            elif verdict == "error":
                # pytest usage/collection error (exit 4/5) mid-run — the harness broke on this
                # mutant, not a real red/green verdict. Never counted as caught or survived.
                errors += 1
            else:
                caught += 1
    finally:
        _restore()

    killed = caught + hung
    total = killed + survived
    rate = f"{killed}/{total}" if total else "0/0"
    hung_note = f", {hung} via-timeout" if hung else ""
    error_note = f", {errors} pytest-errors (excluded)" if errors else ""
    print(
        f"\nKILL-RATE: {rate} caught{hung_note}  ({survived} survived, {skipped} invalid-skipped{error_note})",
        flush=True,
    )
    if survivors:
        print("SURVIVORS (uncaught real mutations — add a test that reddens on each):")
        print("\n".join(survivors[:30]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
