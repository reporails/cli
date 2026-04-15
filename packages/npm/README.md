# @reporails/cli

AI instruction diagnostics for coding agents. Validates instruction files for Claude, Codex, Copilot, Gemini, and Cursor against 90+ deterministic rules.

### Beta — limited 100 spots, free until GA.

## Quick Start

```bash
npx @reporails/cli check
```

That's it. Score and actionable findings — no install, no account.

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

  3 findings · 0 errors · 2 warnings · 1 info
```

## Install

```bash
# Zero install — always latest
npx @reporails/cli check

# Or install globally
npm install -g @reporails/cli
```

Once installed globally, use `ails` directly:

```bash
ails check
ails auth login    # Unlock Pro diagnostics (GitHub sign-in)
ails check         # Now with cross-file analysis + compliance scoring
```

## Supported Agents

| Agent | Instruction files |
|-------|-------------------|
| Claude | `CLAUDE.md`, `.claude/rules/*.md`, `.claude/skills/*/SKILL.md` |
| Codex | `AGENTS.md`, `CODEX.md`, `agents/*.md` |
| Copilot | `copilot-instructions.md`, `.github/copilot-instructions.md` |
| Gemini | `GEMINI.md`, `.gemini/rules/*.md` |
| Cursor | `.cursorrules`, `.cursor/rules/*.md` |

## Commands

| Command | Description |
|---------|-------------|
| `check [PATH]` | Validate instruction files (90+ rules) |
| `explain RULE_ID` | Show rule details and fix guidance |
| `heal` | Auto-fix common violations |
| `auth login` | Sign in with GitHub (Pro enrollment) |
| `auth status` | Check auth state |
| `auth logout` | Remove stored credentials |
| `install [PATH]` | Install MCP server for detected agents |
| `version` | Show version info |

## What It Checks

90+ rules across six categories:

- **Structure** — File organization, size limits, modularity, imports
- **Content** — Specificity, reinforcement, topic clustering, anti-patterns
- **Context Quality** — Tech stack, project description, domain terminology
- **Efficiency** — Token usage, import depth, elaboration
- **Maintenance** — Versioning, review processes
- **Governance** — Security policies, credential protection

## Unauthenticated vs Authenticated

| Feature | Unauthenticated | Authenticated |
|---------|-----------------|---------------|
| Mechanical rules | 70+ | 70+ |
| Deterministic rules | 20+ | 20+ |
| Cross-file analysis | — | Conflicts, repetition |
| Reinforcement detection | — | Orphan instructions, topic clustering |
| Compliance scoring | — | Per-instruction strength |

## GitHub Actions

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
      - run: npx @reporails/cli check --format github --strict
```

## How It Works

Thin Node.js wrapper around the [reporails-cli](https://pypi.org/project/reporails-cli/) Python package. Commands are proxied via `uvx` — no Python install required. Node.js >= 18 needed. `uv` is auto-installed if missing.

## License

[BUSL 1.1](https://github.com/reporails/cli/blob/main/LICENSE) — converts to Apache 2.0 three years after each release.
