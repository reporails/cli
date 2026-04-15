# Reporails CLI

AI instruction diagnostics for coding agents. Validates instruction files for Claude, Codex, Copilot, Gemini, and Cursor against 90+ deterministic rules.

### Beta — limited 100 spots, free until GA. Moving fast, feedback welcome.

## Quick Start

```bash
npx @reporails/cli check
# or
uvx reporails-cli check
```

No install needed. Or install globally:

```bash
npm install -g @reporails/cli    # adds `ails` to PATH
# or
pip install reporails-cli        # same, via Python
```

Then just:

```bash
ails check
```

You'll get a score, level, and actionable findings:

```
Reporails — Diagnostics

  ┌─ Main (1)
  │ CLAUDE.md  12 dir / 5 con · 60% prose
  │   ⚠ L1     No NEVER or AVOID statements found  CORE:C:0003
  │   ○ L1     No version or date marker found  CORE:C:0012
  │
  └─ 3 findings

  ── Summary ──────────────────────────────────────────────

  Score: 7.2 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░  (0.3s)
  Agent: Claude

  Scope:
    capabilities: 1 main
    instructions: 12 directive / 5 prose (28%)
                  5 constraint

  3 findings · 0 errors · 2 warnings · 1 info

  Full diagnostics free for the first 100 registering users during beta
  ails auth login
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
uvx reporails-cli check
```

All paths add `ails` to your PATH. The npm package auto-installs `uv` if needed — no Python install required.

## Authentication

Free offline diagnostics work without an account. For server-enhanced diagnostics (cross-file analysis, reinforcement detection, compliance scoring), sign up for the beta:

```bash
ails auth login       # GitHub Device Flow — authorize in browser
ails auth status      # Check your current auth state
ails auth logout      # Remove stored credentials
```

Credentials are stored in `~/.reporails/credentials.yml`.

## Commands

```bash
ails check                      # Validate your instruction files
ails check -f json              # JSON output
ails check -f github            # GitHub Actions annotations
ails check --strict             # Exit 1 if violations found
ails check --agent claude       # Agent-specific rules only
ails check --exclude-dir vendor # Exclude directory from scanning
ails check -v                   # Verbose: per-file PASS/FAIL with rule titles

ails explain CORE:S:0001        # Explain a specific rule
ails heal                       # Interactive auto-fix for violations
ails install                    # Install MCP server for detected agents
ails version                    # Show version info
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Violations found (strict mode) |
| 2 | Invalid input (bad path, unknown agent/format/rule) |

## Supported Agents

| Agent | Instruction files |
|-------|-------------------|
| Claude | `CLAUDE.md`, `.claude/rules/*.md`, `.claude/skills/*/SKILL.md` |
| Codex | `AGENTS.md`, `CODEX.md`, `agents/*.md` |
| Copilot | `copilot-instructions.md`, `.github/copilot-instructions.md` |
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
# .github/workflows/reporails.yml
name: Reporails
on:
  pull_request:
    paths: ['CLAUDE.md', '.claude/**', 'AGENTS.md', '.cursorrules']
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install reporails-cli
      - run: ails check . --format github --strict
```

## What It Checks

90+ rules across six categories:

- **Structure** — File organization, discoverability, size limits
- **Content** — Clarity, specificity, reinforcement patterns, anti-patterns
- **Context Quality** — Tech stack, project description, domain terminology
- **Efficiency** — Token usage, import depth, instruction elaboration
- **Maintenance** — Versioning, review processes
- **Governance** — Security policies, credential protection, permissions

## Levels [* under re-evaluation *]

Levels describe what your AI instruction setup enables.

| Level | Name | What It Enables |
|-------|------|-----------------|
| L0 | Absent | No instruction file |
| L1 | Present | A non-trivial, tracked instruction file exists |
| L2 | Structured | Project-specific constraints, focused content |
| L3 | Substantive | Modular guidance with external references |
| L4 | Actionable | Instructions adapt based on code location |
| L5 | Refined | Structurally sound, governed, navigable |
| L6 | Adaptive | Agent dynamically discovers context and extends capabilities |

## Offline vs Server

| Feature | Unauthenticated | Authenticated                         |
|---------|-----------------|---------------------------------------|
| Mechanical rules | 70+ rules       | 70+ rules                             |
| Deterministic rules | 20+ rules       | 20+ rules                             |
| Cross-file analysis | -               | Conflicts, repetition                 |
| Reinforcement detection | -               | Orphan instructions, topic clustering |
| Compliance scoring | -               | Per-instruction strength              |
| Rate limit | -               | 10/hour (beta)                        |

## Performance

First run downloads the embedding model (~90MB) to cache. Subsequent runs start in under 2 seconds for typical projects.

## Rules

Rules are bundled with the CLI — no separate install or download needed. See [reporails.com/rules](https://reporails.com/rules) for the full rule reference.

## License

[BUSL 1.1](LICENSE) — converts to Apache 2.0 three years after each release.
