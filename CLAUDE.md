# Reporails CLI v0.2.1

AI instruction validator & quality assurance provider. Validates instruction files against deterministic, mechanical and semantic rules.

## Bootstrap

- Read `.reporails/backbone.yml` for project structure, then `docs/specs/arch.md` for architecture decisions

## Structure

Defined in `.reporails/backbone.yml` — the single source of truth for project topology, paths, and module locations.

**BEFORE** running `find`, `grep`, `ls`, or glob to locate project files, you **MUST** read `.reporails/backbone.yml` first — it defines all project paths, avoiding stale exploratory searches. You **MUST NOT** use exploratory commands to discover paths that the backbone already provides — they produce inconsistent results and waste tokens.

## Development Context

Defined in `.reporails/backbone.yml` under `context`. Don't conflate developer, CLI user, and MCP user personas when discussing features, delivery, or documentation.

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
| `ails check --no-update-check` | Skip pre-run update prompt |
| `ails check --exclude-dir NAME` | Exclude directory from scanning (repeatable) |
| `ails check --strict` | Exit code 1 on violations (CI) |
| `ails check --experimental` | Include experimental-tier rules |
| `ails check -f json` | JSON output (for scripts/MCP) |
| `ails map [PATH]` | Discover project structure |
| `ails map --save` | Save backbone.yml to .reporails/ |
| `ails explain RULE_ID` | Show rule details |
| `ails judge . "RULE:FILE:pass:reason"` | Cache semantic verdicts |
| `ails dismiss RULE_ID` | Dismiss a semantic finding |
| `ails update` | Update rules framework + recommended |
| `ails update --check` | Check for updates without installing |
| `ails update --recommended` | Update recommended rules only |
| `ails update --version VERSION` | Update framework to specific version |
| `ails update --force` | Force reinstall even if current |
| `ails update --cli` | Upgrade CLI package itself |
| `ails version` | Show CLI, framework, and recommended versions |

## Project Structure
```
src/reporails_cli/
├── core/           # Domain logic
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
| Recommended | Downloaded to `~/.reporails/packages/recommended/` | Additional rules (AILS_ namespace) |
| Levels | Downloaded to `~/.reporails/rules/registry/levels.yml` | How to score |
| Capability patterns | Bundled in `src/bundled/capability-patterns.yml` | Feature detection |
| OpenGrep | Downloaded to `~/.reporails/bin/` | Pattern matching |

## Testing

- `uv run poe qa_fast` — Format, lint, pylint structural, type check, unit tests (pre-commit)
- `uv run poe qa` — Full QA including integration tests
- Add unit tests in `tests/unit/` for new functions; add integration tests in `tests/integration/` when OpenGrep interaction changes
- When requirements are ambiguous, ask for clarification rather than guessing

## Code Style

- Formatting and linting enforced by `ruff` (run via `poe qa_fast`) — do not manually reformat
- Naming conventions: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants
- Follow existing patterns in the module you're editing
- Type annotations required on public function signatures

## Architecture

@docs/specs/arch.md for full architecture details.

- **OpenGrep-Powered**: Deterministic pattern matching
- **Framework Separation**: CLI orchestrates, framework defines rules

## Constraints

- NEVER execute destructive or irreversible operations without explicit user confirmation — data loss cannot be undone
- NEVER write ad-hoc scripts — use the project's `uv`/`poe` toolchain (`uv run`, `uv run poe qa_fast`, etc.) to keep tooling consistent
- ALWAYS run `uv run poe qa_fast` after code changes before considering work complete — it catches regressions early

## Memory

Consult auto-memory files in the project memory directory for decisions and patterns from prior sessions. Update memory when you discover stable conventions or resolve recurring issues.