# @reporails/cli

AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 90+ rules.

### Beta — first 100 users free.

## Quick Start

```bash
npx @reporails/cli check
```

No install, no account. Actionable findings in seconds:

```
Reporails — Diagnostics

  ┌─ Main (1)
  │ CLAUDE.md  4 dir / 3 con · 73% prose
  │   ⚠       Missing tech stack declaration  CORE:C:0034
  │   ⚠       Missing testing documentation  CORE:C:0005
  │     2 brief · 2 orphan
  │
  └─ 10 findings

  Score: 7.4 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░  (1.2s)
  10 findings · 8 warnings · 2 info
  Compliance: HIGH
```

## Install

```bash
# One-shot (no install needed)
npx @reporails/cli check

# Permanent install (puts ails on PATH + configures MCP)
npx @reporails/cli install
```

Once installed, use `ails` directly:

```bash
ails check                 # Validate instruction files
ails update                # Upgrade to latest version
ails auth login            # Unlock full diagnostics (GitHub sign-in)
```

## Supported Agents

| Agent   | Instruction files                                         |
|---------|-----------------------------------------------------------|
| Claude  | `CLAUDE.md`, `.claude/rules/*.md`, `.claude/skills/*/SKILL.md` |
| Codex   | `AGENTS.md`, `CODEX.md`, `agents/*.md`                    |
| Copilot | `.github/copilot-instructions.md`                         |
| Gemini  | `GEMINI.md`, `.gemini/rules/*.md`                         |
| Cursor  | `.cursorrules`, `.cursor/rules/*.md`                      |

## Commands

| Command              | Description                                |
|----------------------|--------------------------------------------|
| `check [PATH]`      | Validate instruction files (90+ rules)     |
| `explain RULE_ID`   | Show rule details and fix guidance         |
| `heal`              | Auto-fix common violations                 |
| `auth login`        | Sign in with GitHub                        |
| `auth status`       | Check auth state                           |
| `auth logout`       | Remove stored credentials                  |
| `install [PATH]`    | Install MCP server for detected agents     |
| `version`           | Show version info                          |

## What It Checks

90+ rules across five categories:

- **Structure** — File organization, size limits, modularity
- **Content** — Specificity, reinforcement, tech stack, domain terminology
- **Efficiency** — Token usage, elaboration, formatting
- **Maintenance** — Versioning, review processes
- **Governance** — Security policies, credential protection

## Offline vs Authenticated

| Feature              | Offline     | Authenticated                |
|----------------------|-------------|------------------------------|
| Mechanical checks    | 70+ rules   | 70+ rules                    |
| Content checks       | 25+ rules   | 25+ rules                    |
| Cross-file analysis  | —           | Conflicts, repetition        |
| Compliance scoring   | —           | Per-instruction strength     |

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

Thin Node.js wrapper around [reporails-cli](https://pypi.org/project/reporails-cli/). Commands proxied via `uvx` — no Python install required. Node.js >= 18 needed. `uv` auto-installed if missing.

## License

[BUSL 1.1](https://github.com/reporails/cli/blob/main/LICENSE) — converts to Apache 2.0 three years after each release.
