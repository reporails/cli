# `tests/behave/` — the behavioral demonstration tier (behave / Gherkin)

The integration + e2e tiers of the test pyramid, run as a **separate, first-class
suite** — `uv run behave` (or `uv run poe test_behave`), folded into `qa`, kept out
of the fast unit loop (`qa_fast`).

It lives under `tests/` with every other test tier. It runs under a different
runner than the `pytest` tiers (`behave`, not `pytest`), so `behave.ini` at the repo
root points behave here (`[behave] paths = tests/behave`); `pytest` does not collect
it (`testpaths = ["tests"]` plus the `test_*.py` glob skip the behave files).

## What lives here

- `support.py` — builds a real git project on disk and drives the **real `ails`
  console script via subprocess** (`shutil.which("ails")`); no in-process `CliRunner`.
- `environment.py` — per-scenario tmp project setup/teardown (isolation).
- `<area>.feature` — Gherkin scenarios tagged `@e2e` / `@integration` / `@regression`.
- `steps/` — step definitions wrapping the build+run helpers.

## The rule — a test earns its place

A scenario earns its place only as a **SEAM** (bad input → correct finding; good
input → passes) or a **GUARD** (a regression that actually occurred goes red if it
returns) — never a shape/presence assertion. If reintroducing the bug would not turn
a scenario red, it is decorative; do not add it.

## Enforcement-floor stance

The behavioral tier is the **enforcement floor for composed, multi-step behavior**.
New composed coverage goes *here*, not into more isolated unit-shape assertions in
`tests/unit/`. The bottom (unit) tier stays green and cheap, but "add more unit
tests" is not the answer to a defect that lived in the composed run.
