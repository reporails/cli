# Reporails CLI v0.1.0

AI instruction validator. Validates instruction files against community-maintained rules.

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
uv run ails check .        # Validate (auto-downloads OpenGrep + framework)
uv run ails map . --save   # Save backbone.yml
```

## Commands

| Command | Purpose |
|---------|---------|
| `ails check [PATH]` | Validate instruction files |
| `ails check --refresh` | Force re-scan, ignore cache |
| `ails check --quiet-semantic` | Suppress semantic rules message |
| `ails check -f json` | JSON output (for scripts/MCP) |
| `ails map [PATH]` | Discover project structure |
| `ails map --save` | Save backbone.yml to .reporails/ |
| `ails explain RULE_ID` | Show rule details |
| `ails update` | Update framework to latest |
| `ails version` | Show CLI and framework versions |

## Project Structure
```
src/reporails_cli/
├── core/           # Domain logic
├── bundled/        # CLI-owned config (levels.yml, capability-patterns.yml)
├── interfaces/     # CLI and MCP entry points
└── formatters/     # Output adapters
```

Path-scoped rules in `.claude/rules/` — see those files for context-specific constraints.

See `docs/specs/arch.md` for full architecture.

## Framework vs CLI

| Component | Location | Purpose |
|-----------|----------|---------|
| Rules | Downloaded to `~/.reporails/rules/` | What to check |
| Levels | Bundled in `src/bundled/levels.yml` | How to score |
| OpenGrep | Downloaded to `~/.reporails/bin/` | Pattern matching |

## QA Commands

- `uv run poe qa_fast` — Lint, type check, unit tests (pre-commit)
- `uv run poe qa` — Full QA including integration tests

## Architecture

@docs/specs/arch.md for full architecture details.

- **OpenGrep-Powered**: Deterministic pattern matching
- **Framework Separation**: CLI orchestrates, framework defines rules