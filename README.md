# Reporails CLI

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.
[Why this exists](https://dev.to/cleverhoods/claudemd-lint-score-improve-repeat-2om5)

## Quick Start

### MCP Integration (for Claude Code)

For full semantic analysis, add the MCP server:
```bash
# Add the MCP and restart Claude
claude mcp add reporails -- uvx reporails-cli ails-mcp
```

Then ask Claude: 
```
❯ What ails claude?
```

### CLI path (only deterministic rules)
```bash
# Check your setup (auto-installs OpenGrep + rules on first run)
uvx reporails-cli check .
```

That's it. You'll see:
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
| L1 | Absent | No instruction file |
| L2 | Basic | Has CLAUDE.md |
| L3 | Structured | Sections, imports |
| L4 | Abstracted | .claude/rules/ directory |
| L5 | Governed | Shared files, 3+ components |
| L6 | Adaptive | Backbone + full governance |

## Commands
```bash
ails check .              # Score your setup
ails check . -f json      # JSON output (for CI)
ails check . --strict     # Exit 1 if violations (for CI)
ails map .                # Show project structure
ails map . --save         # Generate backbone.yml
ails explain S1           # Explain a rule
```

## Rules

Rules are maintained separately at [reporails/rules](https://github.com/reporails/rules).

Want to add or improve rules? Contribute there.

## License

Apache 2.0
