# @reporails/cli

AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 97 rules.

### Beta phase — Moving fast, feedback welcome.

## Quick Start

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

No install, no account. Actionable findings in seconds:

```
Reporails — Diagnostics — Pro (beta)

  ┌─ Main (1)
  │ CLAUDE.md
  │   ⚠       Missing directory layout — show the project …  CORE:C:0035
  │   ⚠ L9    7 of 7 instruction(s) lack effective reinfor…  CORE:C:0053
  │     ... and 16 more
  │     1 misordered · 1 orphan · 1 ambiguous
  │
  └─ 21 findings

  Score: 7.9 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░  (1.3s)
  21 findings · 4 warnings · 1 info
  Compliance: HIGH
```

## Install

```bash
# One-shot (no install needed)
npx @reporails/cli check

# Permanent install (puts ails on PATH + configures MCP)
npx @reporails/cli install
# or
uvx --from reporails-cli ails install
```

Once installed, use `ails` directly:

```bash
ails check                 # Validate instruction files
ails update                # Upgrade to latest version
ails auth login            # Unlock full diagnostics (GitHub sign-in)
```

## Supported Agents

| Agent | Base config | Rules | Skills | Agents | Other |
|-------|-------------|-------|--------|--------|-------|
| Claude | `CLAUDE.md`, `.local.md` | `.claude/rules/**/*.md` | `.claude/skills/**/SKILL.md` | `.claude/agents/**/*.md` | commands, output-styles, memory, MCP, settings |
| Codex | `AGENTS.md`, `.override.md` | `.codex/rules/*.rules` | `.agents/skills/**/SKILL.md` | `.codex/agents/*.toml` | hooks, config |
| Copilot | `.github/copilot-instructions.md` | `.github/instructions/**/*.md` | `.github/skills/**/SKILL.md` | `.github/agents/*.agent.md` | hooks, prompts, MCP |
| Cursor | `.cursorrules`, `AGENTS.md` | `.cursor/rules/**/*.mdc` | `.cursor/skills/**/SKILL.md` | `.cursor/agents/*.md` | hooks, notepads, MCP, policy |
| Gemini | `GEMINI.md`, `AGENTS.md` | — | `.gemini/skills/**/SKILL.md` | `.gemini/agents/*.md` | commands, extensions, settings |

Auto-detects which agents are present. Scans project-level, user-level (`~/`), and managed (`/etc/`) paths.

## Commands

| Command | Description |
|---------|-------------|
| `check [PATH]` | Validate instruction files (97 rules) |
| `explain RULE_ID` | Show rule details and fix guidance |
| `heal` | Auto-fix common violations |
| `install [PATH]` | Install CLI to PATH + MCP server |
| `update` | Upgrade to latest version |
| `auth login` | Sign in with GitHub |
| `version` | Show version info |

## What It Checks

97 rules across five categories:

- **Structure** — File organization, size limits, modularity
- **Content** — Specificity, reinforcement, tech stack, domain terminology
- **Efficiency** — Token usage, elaboration, formatting
- **Maintenance** — Versioning, review processes
- **Governance** — Security policies, credential protection

## Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Mechanical + structural rules | 97 rules, full detail | 97 rules, full detail |
| Content-quality checks (embedding-based) | Full detail | Full detail |
| Client checks (ordering, orphan, format, bold, scope) | Full detail | Full detail |
| Per-atom diagnostics (specificity, modality, brevity) | Full detail | Full detail |
| Interaction diagnostics (conflicts, competition, coupling) | Count per file | Full detail (line, fix, effect) |
| Cross-file analysis (conflicts, repetition) | Coordinates only | Full |
| Compliance band + system score | — | Full |

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
