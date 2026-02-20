# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.
[Why this exists](https://dev.to/cleverhoods/claudemd-lint-score-improve-repeat-2om5)

### Pre-1.0 — moving fast, API still evolving, feedback welcome.

## Quick Start

### MCP setup (recommended)

```bash
uvx reporails-cli install
# or
npx @reporails/cli install
```

This detects agents in your project and writes the MCP config. Restart your editor — you'll get validation, scoring, and semantic evaluation via MCP tools.

### CLI-only

```bash
uvx reporails-cli check
# or
npx @reporails/cli check
```

You'll get a score, capability level, and actionable violations:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   SCORE: 8.1 / 10 (awaiting semantic)                        ║
║   LEVEL: Maintained (L5)                                     ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Violations:
  CLAUDE.md (7 issues)
    ○ :1    No NEVER or AVOID statements found       RRAILS:C:0003
    · :1    No version or date marker found           CORE:C:0012
    ...
```

Fix the issues, run again, watch your score improve.

## Install

```bash
pip install reporails-cli
# or
npm install -g @reporails/cli
```

This adds `ails` to your PATH. All commands below assume a global install.

Depends on your install path:

- **uvx/pip**: [uv](https://docs.astral.sh/uv/) — no separate Python install needed
- **npx/npm**: Node.js >= 18 — uv is auto-installed if missing
- **MCP install**: No dependencies — `ails install` writes config files directly

## Commands

### Validate

```bash
ails check                      # Score your setup
ails check -f json              # JSON output
ails check -f github            # GitHub Actions annotations
ails check --strict             # Exit 1 if violations
ails check --agent claude       # Agent-specific rules
ails check --experimental       # Include experimental rules
ails check --exclude-dir vendor # Exclude directory from scanning
ails check -v                   # Verbose: per-file PASS/FAIL with rule titles
ails check --no-update-check    # Skip pre-run update prompt
```

### Fix

```bash
ails heal                       # Auto-fix violations
ails heal -f json               # JSON output for agents and scripts
ails explain CORE:S:0001        # Explain a rule
ails dismiss CORE:C:0001        # Dismiss a semantic finding
```

### Configure

```bash
ails install                    # Install MCP server for detected agents
ails config set default_agent claude  # Set default agent
ails config set --global default_agent claude  # Set global default
ails config get default_agent   # Show current value
ails config list                # Show all config (project + global)
ails map                        # Show project structure
ails map --save                 # Generate backbone.yml
```

### Update

```bash
ails update                     # Update rules framework + recommended
ails update --check             # Check for updates without installing
ails update --recommended       # Update recommended rules only
ails update --force             # Force reinstall even if current
ails update --cli               # Upgrade the CLI package itself
```

Before each scan, the CLI checks for available updates and prompts to install. Use `--no-update-check` to skip. Ephemeral runners (`uvx`, `npx`) always use the latest version automatically.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Violations found (strict mode) |
| 2 | Invalid input (bad path, unknown agent/format/rule) |

## Configuration

Project config in `.reporails/config.yml`:

```yaml
default_agent: claude          # Default agent (run: ails config set default_agent claude)
exclude_dirs: [vendor, dist]   # Directories to skip
disabled_rules: [CORE:C:0010]  # Rules to disable
experimental: false            # Include experimental rules
recommended: true              # Include recommended rules (RRAILS_ namespace)
```

Set values via CLI: `ails config set <key> <value>`

### Global defaults

Global config in `~/.reporails/config.yml` applies to all projects. Project config overrides global.

```bash
ails config set --global default_agent claude   # Use claude everywhere
ails config set --global recommended false      # Opt out globally
```

Supported global keys: `default_agent`, `recommended`.

[Recommended rules](https://github.com/reporails/recommended) (RRAILS_ namespace) are included by default. To opt out: `ails config set recommended false`

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
| `agent` | | Agent type (resolve from project config or generic fallback) |
| `exclude-dir` | | Comma-separated directory names to exclude from scanning |
| `from-source` | `false` | Install CLI from local checkout (for CI testing) |
| `experimental` | `false` | Include experimental rules |
| `version` | | CLI version to install (default: latest) |

**Action outputs:** `score`, `level`, `violations`, `result` (full JSON).

You can also use `--format github` directly in custom workflows:

```bash
ails check . --format github --strict
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
| L1 | Basic | A non-trivial, tracked instruction file exists |
| L2 | Scoped | Project-specific constraints defined, file is focused |
| L3 | Structured | Guidance is modular with external references |
| L4 | Abstracted | Instructions adapt based on code location |
| L5 | Maintained | Instruction system is structurally sound, governed, and navigable |
| L6 | Adaptive | Agent dynamically discovers context and extends capabilities |

## Rules

Core rules are maintained at [reporails/rules](https://github.com/reporails/rules).
Recommended rules at [reporails/recommended](https://github.com/reporails/recommended).

Want to add or improve rules? See the [Contributing guide](https://github.com/reporails/rules/blob/main/CONTRIBUTING.md).

## License

BUSL 1.1
