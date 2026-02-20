# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.
[Why this exists](https://dev.to/cleverhoods/claudemd-lint-score-improve-repeat-2om5)

### Pre-1.0 — moving fast, API still evolving, feedback welcome.

## Quick Start

### One-line setup

```bash
# pip / uvx
ails install

# or via npm (no Python install needed)
npx @reporails/cli install
```

This detects agents in your project and writes the MCP config. Restart your editor, then run `ails check`.

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
pip install reporails-cli
# or
npm install -g @reporails/cli
```

This adds `ails` to your PATH. All commands below assume a global install.

**Try without installing:**
```bash
uvx reporails-cli check
# or
npx @reporails/cli check
```

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

Violations appear as inline annotations on the PR diff. The step summary shows score, level, and a violations table.

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to validate |
| `strict` | `false` | Fail on any violation |
| `min-score` | | Minimum score threshold (0-10) |
| `agent` | `claude` | Agent type |
| `experimental` | `false` | Include experimental rules |
| `version` | | CLI version to install (default: latest) |

**Action outputs:** `score`, `level`, `violations`, `result` (full JSON).

You can also use `--format github` directly in custom workflows:

```bash
ails check . --format github --strict
```

This emits `::error`/`::warning` workflow commands for each violation, plus a JSON summary line.

## Commands

```bash
ails install                    # Install MCP server for detected agents
ails check                      # Score your setup
ails check -f json              # JSON output (for CI)
ails check -f github            # GitHub Actions annotations
ails check --strict             # Exit 1 if violations (for CI)
ails check --no-update-check    # Skip pre-run update prompt
ails check --agent claude       # Agent-specific rules
ails check --experimental       # Include experimental rules
ails check --exclude-dir vendor # Exclude directory from scanning
ails check -v                   # Verbose: per-file PASS/FAIL with rule titles
ails heal                       # Interactive auto-fix + semantic evaluation
ails heal --non-interactive     # JSON output for agents and scripts
ails explain CORE:S:0001        # Explain a rule
ails map                        # Show project structure
ails map --save                 # Generate backbone.yml
ails update                     # Update rules framework + recommended
ails update --check             # Check for updates without installing
ails update --recommended       # Update recommended rules only
ails update --force             # Force reinstall even if current
ails update --cli               # Upgrade the CLI package itself
ails config set default_agent claude  # Set default agent
ails config get default_agent   # Show current value
ails config list                # Show all config
ails dismiss CORE:C:0001        # Dismiss a semantic finding
ails judge . "RULE:FILE:pass:reason"  # Cache semantic verdicts
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

## Configuration

Project config in `.reporails/config.yml`:

```yaml
default_agent: claude          # Default agent (run: ails config set default_agent claude)
exclude_dirs: [vendor, dist]   # Directories to skip
disabled_rules: [CORE:C:0010]  # Rules to disable
experimental: false            # Include experimental rules
recommended: true              # Include recommended rules (AILS_ namespace)
```

Set values via CLI: `ails config set <key> <value>`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Violations found (strict mode) |
| 2 | Invalid input (bad path, unknown agent/format/rule) |

## Prerequisites

Depends on your install path:

- **uvx/pip path**: [uv](https://docs.astral.sh/uv/) — no separate Python install needed
- **npx/npm path**: Node.js >= 18 — uv is auto-installed if missing
- **MCP install**: No dependencies — `ails install` writes config files directly

## Rules

Core rules are maintained at [reporails/rules](https://github.com/reporails/rules).
Recommended rules at [reporails/recommended](https://github.com/reporails/recommended).

Want to add or improve rules? Please follow [Contribute](https://github.com/reporails/rules/blob/main/CONTRIBUTING.md) guide in the [Core repo](https://github.com/reporails/rules).

## License

BUSL 1.1
