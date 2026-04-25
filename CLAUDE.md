# Reporails CLI

AI instruction validator — validates instruction files against mechanical, deterministic, and content_query rules using a pure Python regex engine.

## Session Start

Read `.ails/backbone.yml` for project structure and agent registry. Read `specs/` for architecture decisions before modifying `src/reporails_cli/core/` modules. Specs document the tradeoffs behind current designs and prevent re-solving settled questions.

## Commands

- `uv sync` — install dependencies
- `uv run ails check` — validate instruction files (`-f json` for machine-readable output)
- `uv run ails heal` — interactive auto-fix
- `uv run ails map . --save` — regenerate `backbone.yml`

## Testing

- `uv run poe qa_fast` — lint + type check + unit tests (pre-commit gate)
- `uv run poe qa` — full suite including `tests/integration/` and `tests/smoke/`
- Test files named `test_*.py` with `test_` prefixed functions, using `pytest` fixtures from `conftest.py` for shared setup

## Conventions

- Use `uv run python` to invoke Python — the project virtualenv managed by `uv` has the correct dependencies (`numpy`, `scipy`, `networkx`). Global `python` or `python3` will miss them.
- Use `ruff` for formatting and linting
- Use full rule IDs like `CORE:C:0004` in code and config — not abbreviated forms like `C4`
- Prefer `dataclasses` for data models in `src/reporails_cli/core/pipeline.py` and `src/reporails_cli/core/models.py`
- Keep modules focused on one concern — domain logic in `core/`, entry points in `interfaces/`, output in `formatters/`

## Boundaries

- Scope searches to `src/` or `tests/` using `Grep --type py` for Python files and `Glob "src/**/*.py"` for file discovery. Targeted searches return relevant results faster than broad scans. *Do NOT `grep` the entire repo.*
- Read `specs/` before modifying `src/reporails_cli/core/` modules. Specs contain design constraints that aren't visible in the code alone.
- Sensitive file restrictions (`.env`, `credentials*`, `*.pem`) are in `.claude/rules/sensitive-files.md`

## Architecture

```
src/reporails_cli/
├── core/           # Domain logic (regex/, mechanical/, pipeline, agents)
├── bundled/        # CLI-owned config (capability-patterns.yml)
├── interfaces/     # CLI and MCP entry points
└── formatters/     # Output adapters (json, github, text, mcp)
action/             # GitHub Actions composite action
```

Path-scoped rules in `.claude/rules/` provide context-specific constraints loaded automatically by Claude Code.

## Skills

| Skill                  | Purpose                                        |
|------------------------|------------------------------------------------|
| `/check`               | Self-validate this project's instruction files |
| `/qa`                  | Run the full QA suite                          |
| `/plan-feature`        | Plan implementation of a new feature           |
| `/add-changelog-entry` | Add an entry to `UNRELEASED.md`                |
