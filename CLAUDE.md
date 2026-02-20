# Reporails CLI

- AI instruction validator and quality assurance provider
- Validates instruction files against deterministic, mechanical, and semantic rules
- Pure Python regex engine (no external binary dependencies)

## Session Start

- Read `.reporails/backbone.yml` for project structure
- Read `docs/specs/arch.md` for architecture decisions

## Roles

- **You**: modify source, run tests, read specs
- **CLI end users**: install package, run `ails check`
- **MCP end users**: use reporails via Claude Code
- Treat each role separately when discussing features, delivery, or documentation

## Commands

- `uv sync` — install dependencies
- `uv run ails install` — install MCP server for detected agents
- `uv run ails check` — validate instruction files
- `uv run ails check -f json` — JSON output
- `uv run ails heal` — interactive auto-fix
- `uv run ails map . --save` — save backbone.yml

## Testing

- `uv run poe qa_fast` — lint + type check + unit tests (pre-commit gate)
- `uv run poe qa` — full QA including integration and smoke tests
- Unit tests in `tests/unit/`, integration tests in `tests/integration/`, smoke in `tests/smoke/`
- Test files named `test_*.py`, test functions prefixed `test_`
- Use `pytest` fixtures from `conftest.py` for shared setup
- NEVER modify golden fixtures; update the corresponding expected output instead

## Architecture

```
src/reporails_cli/
├── core/           # Domain logic (regex/, mechanical/, pipeline, agents)
├── bundled/        # CLI-owned config (capability-patterns.yml)
├── interfaces/     # CLI and MCP entry points
└── formatters/     # Output adapters (json, github, text, mcp)
action/             # GitHub Actions composite action
```

- Path-scoped rules in `.claude/rules/` — see those files for context-specific constraints
- See `docs/specs/arch.md` for full architecture

## Conventions

- Requires Python >=3.10 with type annotations on public APIs
- Use `ruff` for formatting and linting
- Module layout: domain logic in `core/`, entry points in `interfaces/`, output in `formatters/`
- Prefer dataclasses for data models (`pipeline.py`, `models.py`)
- Keep modules focused — one concern per file
- Use full rule IDs in code and config (e.g., `CORE:C:0004`, not `C4`)
- When fixing bugs, explain the root cause and why the fix works
- When making architectural decisions, document the tradeoffs considered

## Boundaries

- NEVER read or modify sensitive files (`.env`, `credentials*`, `*.pem`); ask the user instead
- NEVER grep the entire repo; scope searches to `src/` or `tests/` instead
- ALWAYS read specs (`docs/specs/*.md`) before modifying core modules
- Prefer reading specific files over broad glob patterns
- Use `Grep --type py` for Python-specific searches
- Use `Glob "src/**/*.py"` to find Python files

## Skills

| Skill | Purpose |
|-------|---------|
| `/check` | Self-validate this project's instruction files |
| `/qa` | Run the full QA suite |
| `/plan-feature` | Plan implementation of a new feature |
| `/add-changelog-entry` | Add an entry to UNRELEASED.md |