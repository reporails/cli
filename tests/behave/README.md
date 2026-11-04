# `tests/behave/` — the behavioral demonstration tier (behave / Gherkin)

The integration + e2e tiers of the test pyramid, run as a **separate, first-class
suite** — `uv run behave` (or `uv run poe test_behave`), folded into `qa`, kept out
of the fast unit loop (`qa_fast`).

It lives under `tests/` with every other test tier. It runs under a different
runner than the `pytest` tiers (`behave`, not `pytest`), so `behave.ini` at the repo
root points behave here (`[behave] paths = tests/behave`); `pytest` does not collect
it (`testpaths = ["tests"]` plus the `test_*.py` glob skip the behave files).

## Running it

- All features, in parallel: `uv run poe test_behave` (runs `scripts/behave_parallel.py`). It splits the scenarios over `min(4, cpu_count // 2)` concurrent `behave` processes, balanced longest-first from the previous run's JUnit times (`tmp/behave-junit/`), then prints per-feature status and time, the ten slowest scenarios and the total wall time. It exits non-zero when any process fails. Extra arguments go to every `behave` process: `uv run poe test_behave --tags=-api`.
- On Linux with `powerprofilesctl`, the parallel run holds the `performance` power profile while it runs, and the previous profile returns when it ends: a laptop on its balanced profile caps the clock under multi-core load, and the suite then takes about twice as long. `BEHAVE_POWER=keep uv run poe test_behave` leaves the profile alone.
- One feature or one scenario, serial: `uv run behave tests/behave/check.feature` or `uv run behave tests/behave/check.feature:12`.
- Everything serial: `uv run behave`.
- Each `behave` process starts one headless Chrome in `before_all` (free port, own profile) and exports `XRAY_CDP_URL`; every `xray_*.mjs` script opens a tab in it. Without `XRAY_CDP_URL` a script spawns a Chrome of its own, so `node tests/behave/xray_tables.mjs <url> <mode>` still runs standalone. Set `XRAY_DEBUG=<file>` to log each page wait that timed out.

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
