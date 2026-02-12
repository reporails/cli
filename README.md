# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.
[Why this exists](https://dev.to/cleverhoods/claudemd-lint-score-improve-repeat-2om5)

### Pre-1.0 — moving fast, API still evolving, feedback welcome.

## Quick Start

### One-line install (npm)

```bash
npx @reporails/cli install
```

This registers the MCP server with Claude Code. Then ask Claude: `What ails claude?`

### MCP Integration (manual)

For full semantic analysis, add the MCP server:
```bash
# Add the MCP and restart Claude
claude mcp add reporails -- uvx --refresh --from reporails-cli ails-mcp
```

Then ask Claude:
```
❯ What ails claude?
```

### CLI path (only deterministic rules)
```bash
# No install needed — run directly
uvx reporails-cli check
# or
npx @reporails/cli check
```

That's it. You'll get a score, capability level, and actionable violations.
```
╔══════════════════════════════════════════════════════════════╗
║   SCORE: 8.1 / 10 (partial)  |  CAPABILITY: Maintained (L5)    ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░         ║
╚══════════════════════════════════════════════════════════════╝

Violations:
  CLAUDE.md (7 issues)
    ○ MED C4.no-antipatterns :1    No NEVER or AVOID statements found
    · LOW C12.no-version     :1    No version or date marker found
    ...
```

Fix the issues, run again, watch your score and your experience improve.

## Install

```bash
# Ephemeral (no install, always latest)
uvx reporails-cli check
npx @reporails/cli check

# Persistent (adds `ails` to PATH)
pip install reporails-cli
# or
npm install -g @reporails/cli
```

Once installed, all commands use `ails` directly.

## What It Checks

- **Structure** — File organization, size limits
- **Content** — Clarity, completeness, anti-patterns
- **Efficiency** — Token usage, context management
- **Maintenance** — Versioning, review processes
- **Governance** — Ownership, security policies

## Capability Levels

Capability levels describe what your AI instruction setup enables — not how "mature" it is. Different projects need different capabilities.

| Level | Name | What It Enables |
|-------|------|-----------------|
| L0 | Absent | No instruction file — nothing to evaluate |
| L1 | Basic | Reviewed, tracked instruction file |
| L2 | Scoped | Project-specific constraints, size control |
| L3 | Structured | External references, multiple files |
| L4 | Abstracted | Path-scoped rules, context-aware loading |
| L5 | Maintained | Structural integrity, governance, navigation |
| L6 | Adaptive | Dynamic context, extensibility, persistence |

## Commands

```bash
ails check                      # Score your setup
ails check -f json              # JSON output (for CI)
ails check --strict             # Exit 1 if violations (for CI)
ails check --no-update-check    # Skip pre-run update prompt
ails check --exclude-dir vendor # Exclude directory from scanning
ails explain CORE:S:0001        # Explain a rule
ails map                        # Show project structure
ails map --save                 # Generate backbone.yml
ails update                     # Update rules framework + recommended
ails update --check             # Check for updates without installing
ails update --recommended       # Update recommended rules only
ails update --force             # Force reinstall even if current
ails update --cli               # Upgrade the CLI package itself
ails dismiss CORE:C:0001        # Dismiss a semantic finding
ails version                    # Show version info
```

## Updating

```bash
ails update              # Update rules framework + recommended to latest
ails update --check      # Check for updates without installing
ails update --recommended  # Update recommended rules only
ails update --force      # Force reinstall even if current
ails update --cli        # Upgrade the CLI package itself
```

Before each scan, the CLI checks for available updates and prompts to install. Use `--no-update-check` to skip.

Ephemeral runners (`uvx`, `npx`) always use the latest CLI version automatically.

## Recommended Rules

[Recommended rules](https://github.com/reporails/recommended) (AILS_ namespace) are included by default and auto-downloaded on first run. To opt out, add to your `.reporails/config.yml`:

```yaml
recommended: false
```

To update recommended rules independently:

```bash
ails update --recommended
```

## Prerequisites

Depends on your install path:

- **uvx/pip path**: [uv](https://docs.astral.sh/uv/) — no separate Python install needed
- **npx/npm path**: Node.js >= 18 — uv is auto-installed if missing
- **MCP install/uninstall**: [Claude Code](https://docs.anthropic.com/en/docs/claude-code)

## Rules

Core rules are maintained at [reporails/rules](https://github.com/reporails/rules).
Recommended rules at [reporails/recommended](https://github.com/reporails/recommended).

Want to add or improve rules? Please follow [Contribute](https://github.com/reporails/rules/blob/main/CONTRIBUTING.md) guide in the [Core repo](https://github.com/reporails/rules).

## License

BUSL 1.1
