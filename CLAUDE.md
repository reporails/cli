# Reporails CLI v0.3.0

AI instruction validator & quality assurance provider. Validates instruction files against deterministic, mechanical and semantic rules using a pure Python regex engine.

## Session Start

1. Read `.reporails/backbone.yml` for project structure
2. Read `docs/specs/arch.md` for architecture decisions

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

## Quick Start
```bash
uv sync                    # Install dependencies
uv run ails check           # Validate (auto-downloads framework rules)
uv run ails map . --save   # Save backbone.yml
```

## Commands

| Command | Purpose |
|---------|---------|
| `ails check [PATH]` | Validate instruction files |
| `ails check --refresh` | Force re-scan, ignore cache |
| `ails check --quiet-semantic` | Suppress semantic rules message |
| `ails check -f json` | JSON output (for scripts/MCP) |
| `ails heal [PATH]` | Interactive auto-fix + semantic evaluation |
| `ails dismiss RULE FILE` | Dismiss a semantic rule for a file |
| `ails judge PATH VERDICTS...` | Cache semantic rule verdicts |
| `ails map [PATH]` | Discover project structure |
| `ails map --save` | Save backbone.yml to .reporails/ |
| `ails explain RULE_ID` | Show rule details |
| `ails update` | Update rules framework to latest |
| `ails update --cli` | Upgrade CLI package itself |
| `ails version` | Show CLI and framework versions |

## Project Structure
```
src/reporails_cli/
├── core/           # Domain logic (regex/, mechanical/, pipeline, agents)
├── bundled/        # CLI-owned config (capability-patterns.yml)
├── interfaces/     # CLI and MCP entry points
└── formatters/     # Output adapters
```

Path-scoped rules in `.claude/rules/` — see those files for context-specific constraints.

See `docs/specs/arch.md` for full architecture.

## Framework vs CLI

| Component | Location | Purpose |
|-----------|----------|---------|
| Rules | Downloaded to `~/.reporails/rules/` | What to check |
| Levels | Loaded from framework `registry/levels.yml` | How to score |
| Regex Engine | Built-in pure Python | Pattern matching |

## Testing

- Run `uv run poe qa_fast` for lint + type check + unit tests (pre-commit gate)
- Run `uv run poe qa` for full QA including integration tests
- Unit tests in `tests/unit/`, integration tests in `tests/integration/`
- Test files named `test_*.py`, test functions prefixed `test_`
- Use `pytest` fixtures from `conftest.py` for shared setup
- Never modify golden fixtures — update expected output alongside

## Conventions

- Python 3.10+ with type annotations on public APIs
- Use `ruff` for formatting and linting
- Module layout: domain logic in `core/`, entry points in `interfaces/`, output in `formatters/`
- Prefer dataclasses for data models (`pipeline.py`, `models.py`)
- Keep modules focused — one concern per file
- Use full rule IDs in code and config (e.g., `CORE:C:0004`, not `C4`)

## Architecture

@docs/specs/arch.md for full architecture details.

- **Pure Python Regex**: Deterministic pattern matching via built-in regex engine
- **Framework Separation**: CLI orchestrates, framework defines rules