# @reporails/cli

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.

## Quick Start

```bash
npx @reporails/cli install
```

This registers the MCP server with Claude Code. Then ask Claude:

```
> What ails claude?
```

### CLI path (only deterministic rules)

```bash
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
npx @reporails/cli check

# Persistent (adds `ails` to PATH)
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

| Level | Name | What it means |
|-------|------|---------------|
| L1 | Absent | No instruction file |
| L2 | Basic | Has CLAUDE.md |
| L3 | Structured | Sections, imports |
| L4 | Abstracted | .claude/rules/ directory |
| L5 | Maintained | Shared files, 3+ components |
| L6 | Adaptive | Backbone + full governance |

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

| Command | Description |
|---------|-------------|
| `install [--scope user\|project]` | Register MCP server with Claude Code |
| `uninstall [--scope user\|project]` | Remove MCP server from Claude Code |
| `check [PATH]` | Validate instruction files |
| `explain RULE_ID` | Show rule details |
| `map [PATH]` | Discover project structure |
| `update` | Update rules framework + recommended |
| `dismiss RULE_ID` | Dismiss a semantic finding |
| `version` | Show version info |

## Updating

```bash
ails update              # Update rules framework + recommended to latest
ails update --check      # Check for updates without installing
ails update --recommended  # Update recommended rules only
ails update --force      # Force reinstall even if current
ails update --cli        # Upgrade the CLI package itself
```

Before each scan, the CLI prompts when updates are available. Use `--no-update-check` to skip.

The **CLI itself** updates automatically — `npx @reporails/cli` always fetches the latest version.
Persistent installs: `npm install -g @reporails/cli@latest`

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

- **Node.js >= 18**
- **uv** — auto-installed if missing ([manual install](https://docs.astral.sh/uv/))
- **Claude Code** — required for `install`/`uninstall` commands ([install](https://docs.anthropic.com/en/docs/claude-code))

## How It Works

This is a thin Node.js wrapper around the [reporails-cli](https://pypi.org/project/reporails-cli/) Python package. Commands are proxied via `uvx` — no Python installation required.

## Rules

Core rules are maintained at [reporails/rules](https://github.com/reporails/rules).
Recommended rules at [reporails/recommended](https://github.com/reporails/recommended).

Want to add or improve rules? Please follow [Contribute](https://github.com/reporails/rules/blob/main/CONTRIBUTING.md) guide in the [Core repo](https://github.com/reporails/rules).

## License

BUSL 1.1
