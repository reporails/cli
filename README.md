# Reporails CLI

AI instruction diagnostics for coding agents. Validates CLAUDE.md, AGENTS.md, .cursorrules, and other instruction files against 90+ rules.

### Beta — first 100 users free. Moving fast, feedback welcome.

## Quick Start

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

No install needed. Or install globally:

```bash
npm install -g @reporails/cli
# or
pip install reporails-cli
```

Then just:

```bash
ails check
```

```
Reporails — Diagnostics

  ┌─ Main (1)
  │ CLAUDE.md  4 dir / 3 con · 73% prose
  │   ⚠       Missing tech stack declaration  CORE:C:0034
  │   ⚠       Missing testing documentation  CORE:C:0005
  │     2 brief · 2 orphan
  │
  └─ 10 findings

  ── Summary ──────────────────────────────────────────────

  Score: 7.4 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░  (1.2s)
  Agent: Claude

  Scope:
    capabilities: 1 main
    instructions: 4 directive / 11 prose (73%)
                  3 constraint

  10 findings · 8 warnings · 2 info
  Compliance: HIGH
```

Fix the issues, run again, watch your score improve.

## Install

```bash
# Node.js (recommended — no separate Python install needed)
npm install -g @reporails/cli

# Python
pip install reporails-cli

# Zero install (ephemeral, always latest)
npx @reporails/cli check
uvx --from reporails-cli ails check
```

All paths register `ails` on your PATH. The npm package auto-installs `uv` if needed.

## Authentication

Offline diagnostics work without an account. For server-enhanced diagnostics (cross-file analysis, compliance scoring), sign up for the beta:

```bash
ails auth login       # GitHub Device Flow — authorize in browser
ails auth status      # Check current auth state
ails auth logout      # Remove stored credentials
```

## Commands

```bash
ails check                       # Validate instruction files
ails check -f json               # JSON output
ails check -f github             # GitHub Actions annotations
ails check --strict              # Exit 1 on any finding
ails check --agent claude        # Agent-specific rules only
ails check --exclude-dirs vendor # Exclude directory from scanning
ails check -v                    # Verbose: all findings with rule IDs

ails explain CORE:S:0001         # Explain a specific rule
ails heal                        # Auto-fix common violations
ails install                     # Install MCP server for detected agents
ails version                     # Show version info
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Findings found (strict mode) |
| 2 | Invalid input (bad path, unknown agent/format/rule) |

## Supported Agents

| Agent | Instruction files |
|-------|-------------------|
| Claude | `CLAUDE.md`, `.claude/rules/*.md`, `.claude/skills/*/SKILL.md` |
| Codex | `AGENTS.md`, `CODEX.md`, `agents/*.md` |
| Copilot | `.github/copilot-instructions.md` |
| Gemini | `GEMINI.md`, `.gemini/rules/*.md` |
| Cursor | `.cursorrules`, `.cursor/rules/*.md` |

The CLI auto-detects which agents are present in your project.

## Configuration

Project config in `.ails/config.yml`:

```yaml
default_agent: claude          # Default agent (run: ails config set default_agent claude)
exclude_dirs: [vendor, dist]   # Directories to skip
disabled_rules: [CORE:C:0010]  # Rules to disable
```

Set values via CLI: `ails config set <key> <value>`

### Global defaults

Global config in `~/.reporails/config.yml` applies to all projects. Project config overrides global.

```bash
ails config set --global default_agent claude
```

## GitHub Actions

Add `ails check` as a CI gate with inline PR annotations:

```yaml
name: Reporails
on:
  pull_request:
    paths: ['CLAUDE.md', '.claude/**', 'AGENTS.md', '.cursorrules']
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: reporails/cli/action
        with:
          strict: "true"
```

Or without the action:

```yaml
      - run: pip install reporails-cli && ails check . --format github --strict
```

## What It Checks

90+ rules across five categories:

- **Structure** — File organization, discoverability, size limits, modularity
- **Content** — Clarity, specificity, reinforcement patterns, tech stack, domain terminology
- **Efficiency** — Token usage, instruction elaboration, formatting
- **Maintenance** — Versioning, review processes
- **Governance** — Security policies, credential protection, permissions

## Offline vs Authenticated

| Feature | Offline | Authenticated |
|---------|---------|---------------|
| Mechanical checks | 70+ rules | 70+ rules |
| Content-quality checks | 25+ rules | 25+ rules |
| Cross-file analysis | — | Conflicts, repetition |
| Compliance scoring | — | Per-instruction strength |

## Performance

The embedding model is bundled in the wheel. First run may download the spaCy language model (~13 MB). Subsequent runs complete in under 2 seconds for typical projects.

## Rules

Rules are bundled with the CLI — no separate install needed. See [reporails.com/rules](https://reporails.com/rules) for the full reference.

## License

[BUSL 1.1](LICENSE) — converts to Apache 2.0 three years after each release.
