# @reporails/cli

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.

## Quick Start

```bash
npx @reporails/cli install
```

This detects agents in your project and writes the MCP config. Then ask Claude:

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
║   SCORE: 8.1 / 10 (awaiting semantic)  |  CAPABILITY: Maintained (L5)    ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░         ║
╚══════════════════════════════════════════════════════════════╝

Violations:
  CLAUDE.md (7 issues)
    ○ :1    No NEVER or AVOID statements found       RRAILS:C:0003
    · :1    No version or date marker found           CORE:C:0012
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

## GitHub Actions

Add `ails check` as a CI gate with inline PR annotations:

```yaml
# .github/workflows/reporails.yml
name: Reporails
on:
  pull_request:
    paths: ['CLAUDE.md', '.claude/**']
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: reporails/cli/action@v1
        with:
          min-score: '6.0'
```

See the [main README](https://github.com/reporails/cli#github-actions) for full action inputs/outputs.

## Commands

| Command | Description |
|---------|-------------|
| `install [PATH]` | Install MCP server for detected agents |
| `check [PATH]` | Validate instruction files |
| `heal [PATH]` | Interactive auto-fix + semantic evaluation |
| `explain RULE_ID` | Show rule details |
| `map [PATH]` | Discover project structure |
| `update` | Update rules framework + recommended |
| `config set KEY VALUE` | Set a project config value |
| `config set --global KEY VALUE` | Set a global default |
| `config get KEY` | Show a config value |
| `config list` | Show all config (project + global) |
| `dismiss RULE_ID` | Dismiss a semantic finding |
| `judge PATH VERDICTS` | Cache semantic verdicts |
| `version` | Show version info |

See the [main README](https://github.com/reporails/cli#commands) for full flag reference.

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

[Recommended rules](https://github.com/reporails/recommended) (AILS_ namespace) are included by default and auto-downloaded on first run. To opt out:

```bash
ails config set recommended false            # This project only
ails config set --global recommended false   # All projects
```

To update recommended rules independently:

```bash
ails update --recommended
```

## Prerequisites

- **Node.js >= 18**
- **uv** — auto-installed if missing ([manual install](https://docs.astral.sh/uv/))
- **No additional dependencies** — `install` writes config files directly

## How It Works

This is a thin Node.js wrapper around the [reporails-cli](https://pypi.org/project/reporails-cli/) Python package. Commands are proxied via `uvx` — no Python installation required.

## Rules

Core rules are maintained at [reporails/rules](https://github.com/reporails/rules).
Recommended rules at [reporails/recommended](https://github.com/reporails/recommended).

Want to add or improve rules? Please follow [Contribute](https://github.com/reporails/rules/blob/main/CONTRIBUTING.md) guide in the [Core repo](https://github.com/reporails/rules).

## License

BUSL 1.1 — converts to Apache 2.0 on 2029-02-20 or at 1.0, whichever comes first.
