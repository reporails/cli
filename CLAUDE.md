# Reporails CLI

AI instruction linter. Validates instruction files against community-maintained rules.

**repoRAILS** = **Repo** **R**ecursive **AI** **L**inting**S**

## Development Context

You are developing the reporails CLI, not an end user.

- **You**: modify source, run tests, read specs
- **CLI end users**: install package, run `ails check`
- **MCP end users**: use reporails via Claude Code

Don't conflate these when discussing features, delivery, or documentation.

## Session Start

1. Read `.reporails/backbone.yml` for project structure
2. Read `docs/specs/arch.md` for architecture decisions
3. Read `docs/specs/modules.md` before modifying core modules

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

See `docs/specs/arch.md` for full architecture.

## Framework vs CLI

| Component | Location | Purpose |
|-----------|----------|---------|
| Rules | Downloaded to `~/.reporails/rules/` | What to check |
| Levels | Bundled in `src/bundled/levels.yml` | How to score |
| OpenGrep | Downloaded to `~/.reporails/bin/` | Pattern matching |

## QA Commands

| Command | Purpose |
|---------|---------|
| `uv run poe qa_fast` | Lint, type check, unit tests |
| `uv run poe qa` | Full QA including integration |
| `uv run poe lint` | Ruff linter |
| `uv run poe format` | Format code |
| `uv run poe type` | Mypy type checking |

## Architecture

- **Agent-Agnostic**: Detects Claude, Cursor, Windsurf, Copilot, Aider
- **Claude Rules v0.0.1**: Linting rules currently for Claude only
- **OpenGrep-Powered**: Deterministic pattern matching
- **Two-Phase Detection**: Filesystem + content analysis for capability scoring
- **Framework Separation**: CLI orchestrates, framework defines rules