# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.
[Why this exists](https://dev.to/cleverhoods/claudemd-lint-score-improve-repeat-2om5)

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
║   SCORE: 8.1 / 10 (partial)  |  CAPABILITY: Governed (L5)    ║
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

| Level | Name | What it means |
|-------|------|---------------|
| L1 | Absent | No instruction file |
| L2 | Basic | Has CLAUDE.md |
| L3 | Structured | Sections, imports |
| L4 | Abstracted | .claude/rules/ directory |
| L5 | Governed | Shared files, 3+ components |
| L6 | Adaptive | Backbone + full governance |

## Commands

```bash
ails check                      # Score your setup
ails check -f json              # JSON output (for CI)
ails check --strict             # Exit 1 if violations (for CI)
ails check --with-recommended   # Include recommended rules
ails explain S1                 # Explain a rule
ails map                        # Show project structure
ails map --save                 # Generate backbone.yml
ails update                     # Update rules framework
ails update --check             # Check for rule updates
ails dismiss C6                 # Dismiss a semantic finding
ails version                    # Show version info
```

## Updating

The **rules framework** updates separately from the CLI:

```bash
ails update              # Update rules to latest
ails update --check      # Check without installing
```

The **CLI itself** updates automatically with ephemeral runners (`uvx`, `npx`).
Persistent installs: `pip install --upgrade reporails-cli` or `npm install -g @reporails/cli@latest`

## Recommended Rules

The `--with-recommended` flag adds community [recommended rules](https://github.com/reporails/recommended) on top of the core set. These are methodology-backed checks (AILS_ namespace) that are auto-downloaded on first use:

```bash
ails check --with-recommended       # Include recommended rules
ails update --recommended              # Re-fetch latest recommended rules
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

Apache 2.0
