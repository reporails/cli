# Reporails CLI

AI instruction linter. Currently supports Claude. Detection finds other agents (Cursor, Windsurf, Copilot, Aider) for future support.

## Development Context

You are developing the reporails CLI, not an end user.

- **You**: modify source, run tests, access framework repo (GitHub MCP) for rule rationale
- **CLI end users**: install and run `ails`
- **MCP end users**: use reporails via Claude Code

Don't conflate these when discussing features, delivery, or documentation.

## Session Start

1. Read `.reporails/backbone.yml` for project structure
2. Read `docs/specs/arch.md` if making architectural changes
3. NEVER modify `checks/**/*.md` without explicit human instruction

## Quick Start

```bash
uv sync                                  # Install dependencies
uv run ails check . --checks-dir checks  # Validate instruction files
uv run ails map . --save                 # Save backbone.yml to repo
```

## Commands

| Command | Purpose |
|---------|---------|
| `ails check PATH` | Validate instruction files (auto-installs on first run) |
| `ails check PATH --refresh` | Force re-scan, ignore cache |
| `ails map PATH` | Map project structure, find instruction files |
| `ails map PATH --save` | Save `backbone.yml` to `.reporails/` |
| `ails explain RULE_ID` | Show rule details |
| `ails sync checks` | Sync .md rule definitions from framework repo (dev) |

## Rule Files

- `checks/**/*.yml` — OpenGrep patterns (tracked in CLI repo)
- `checks/**/*.md` — Rule definitions (gitignored, symlinked to framework)

**Dev setup:** Run `./scripts/link-rules.sh` to symlink .md files from framework repo.
Edits in `checks/*.md` go to `../framework/rules/` (same file via symlink).

## Project Structure

See `docs/specs/arch.md` for full architecture, `.reporails/backbone.yml` for file map.

## QA Commands

| Command | Purpose |
|---------|---------|
| `uv run poe qa_fast` | Lint, type check, unit tests |
| `uv run poe qa` | Full QA including integration |
| `uv run poe lint` | Ruff linter |
| `uv run poe format` | Format code |
| `uv run poe type` | Mypy type checking |

## Architecture

- **Claude-First**: Linting rules for Claude instruction files (v0.0.1)
- **Discovery-Ready**: Detects other agents for future support
- **OpenGrep-Powered**: Pattern matching via OpenGrep binary
- **Backbone-Driven**: Discovery generates dependency graph
- **Cached**: File maps avoid repeated filesystem scans
