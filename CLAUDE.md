# Reporails CLI

AI instruction validator & quality assurance provider. Validates instruction files against deterministic, mechanical and semantic rules using a pure Python regex engine.

## Session Start

Read `.reporails/backbone.yml` for project structure and `docs/specs/arch.md` for architecture decisions.

## Development Context

You are developing the reporails CLI, not an end user.

- **You**: modify source, run tests, read specs
- **CLI end users**: install package, run `ails check`
- **MCP end users**: use reporails via Claude Code

Don't conflate these when discussing features, delivery, or documentation.

## File Reading Strategy

- Read specs (`docs/specs/*.md`) before modifying core modules
- Prefer reading specific files over broad glob patterns

## Search Efficiency

- Use `Grep --type py` for Python-specific searches
- Use `Glob "src/**/*.py"` to find Python files
- Limit searches to `src/` or `tests/` directories when possible
- Avoid grepping the entire repo; scope to relevant paths

## Quick Reference

- `uv sync` to install dependencies
- `uv run ails setup` to set up MCP server for detected agents
- `uv run ails check` to validate instruction files
- `uv run ails check -f json` for JSON output
- `uv run ails heal` for interactive auto-fix
- `uv run ails map . --save` to save backbone.yml

## Project Structure
```
src/reporails_cli/
├── core/           # Domain logic (regex/, mechanical/, pipeline, agents)
├── bundled/        # CLI-owned config (capability-patterns.yml)
├── interfaces/     # CLI and MCP entry points
└── formatters/     # Output adapters (json, github, text, mcp)
action/             # GitHub Actions composite action
```

Path-scoped rules in `.claude/rules/` — see those files for context-specific constraints.

See `docs/specs/arch.md` for full architecture.

## Testing

- Run `uv run poe qa_fast` for lint + type check + unit tests (pre-commit gate)
- Run `uv run poe qa` for full QA including integration tests
- Unit tests in `tests/unit/`, integration tests in `tests/integration/`
- Test files named `test_*.py`, test functions prefixed `test_`
- Use `pytest` fixtures from `conftest.py` for shared setup
- Never modify golden fixtures — update expected output alongside

## Conventions

- Requires Python >=3.10 with type annotations on public APIs
- Use `ruff` for formatting and linting
- Module layout: domain logic in `core/`, entry points in `interfaces/`, output in `formatters/`
- Prefer dataclasses for data models (`pipeline.py`, `models.py`)
- Keep modules focused — one concern per file
- Use full rule IDs in code and config (e.g., `CORE:C:0004`, not `C4`)
- When fixing bugs, explain the root cause and why the fix works
- When making architectural decisions, document the tradeoffs considered

## Skills

| Skill | Purpose |
|-------|---------|
| `/check` | Self-validate this project's instruction files |
| `/qa` | Run the full QA suite |
| `/plan-feature` | Plan implementation of a new feature |
| `/add-changelog-entry` | Add an entry to UNRELEASED.md |

## Architecture

@docs/specs/arch.md for full architecture details.