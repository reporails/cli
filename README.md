# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.

## Quick Start

```bash
# Install (downloads OpenGrep automatically)
uvx reporails-cli init

# Check your setup
ails check .
```

That's it. You'll see:

```
╔══════════════════════════════════════════════════════════════╗
║   SCORE: 6.3 / 10 (partial)  |  CAPABILITY: Governed (L5)    ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░         ║
╚══════════════════════════════════════════════════════════════╝

Violations:
  CLAUDE.md (7 issues)
    ○ MED C4.no-antipatterns :1    No NEVER or AVOID statements found
    · LOW C12.no-version     :1    No version or date marker found
    ...
```

Fix the issues, run again, watch your score improve.

## What It Checks

- **Structure** — File organization, size limits
- **Content** — Clarity, completeness, anti-patterns
- **Efficiency** — Token usage, context management
- **Maintenance** — Versioning, review processes
- **Governance** — Ownership, security policies

## Capability Levels

| Level | Name | What it means |
|-------|------|---------------|
| L1 | Minimal | Just a CLAUDE.md |
| L2 | Basic | Structured sections |
| L3 | Structured | .claude/rules/ directory |
| L4 | Managed | Backbone + automation |
| L5 | Governed | Full governance setup |

## MCP Integration (for Claude Code)

For full semantic analysis, add the MCP server:

```bash
claude mcp add reporails -- uvx --from reporails-cli ails-mcp
```

Then ask Claude: "Check my CLAUDE.md setup"

## Commands

```bash
ails check .              # Score your setup
ails check . -f json      # JSON output (for CI)
ails map . --save         # Generate backbone.yml
ails explain S1           # Explain a rule
```

## License

Apache 2.0