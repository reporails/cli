# Reporails CLI

AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 90+ rules.

### Beta — first 100 users free. Moving fast, feedback welcome.

## Quick Start

```bash
npx @reporails/cli check
```

## Install

```bash
npx @reporails/cli install
```

This installs `ails` to your PATH and configures the MCP server for detected agents. From then on:

```bash
ails check
ails update               # Upgrade to latest version
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
ails install                     # Install CLI to PATH + MCP server
ails update                      # Upgrade to latest version
ails version                     # Show version info
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Findings found (strict mode) |
| 2 | Invalid input (bad path, unknown agent/format/rule) |

## Supported Agents

| Agent | Base config | Rules | Skills | Agents | Other |
|-------|-------------|-------|--------|--------|-------|
| Claude | `CLAUDE.md`, `.local.md` | `.claude/rules/**/*.md` | `.claude/skills/**/SKILL.md` | `.claude/agents/**/*.md` | commands, output-styles, memory, MCP, settings |
| Codex | `AGENTS.md`, `.override.md` | `.codex/rules/*.rules` | `.agents/skills/**/SKILL.md` | `.codex/agents/*.toml` | hooks, config |
| Copilot | `.github/copilot-instructions.md` | `.github/instructions/**/*.md` | `.github/skills/**/SKILL.md` | `.github/agents/*.agent.md` | hooks, prompts, MCP |
| Cursor | `.cursorrules`, `AGENTS.md` | `.cursor/rules/**/*.mdc` | `.cursor/skills/**/SKILL.md` | `.cursor/agents/*.md` | hooks, notepads, MCP, policy |
| Gemini | `GEMINI.md`, `AGENTS.md` | — | `.gemini/skills/**/SKILL.md` | `.gemini/agents/*.md` | commands, extensions, settings |

Auto-detects which agents are present. Scans project-level, user-level (`~/`), and managed (`/etc/`) paths.

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

Free tier requires no account. Pro shows you *how many* interaction problems exist and *where* cross-file conflicts are — enough to know if your instructions are working. Pro gives the full detail: which line, what to fix, and how strong the effect is.

## Performance

The embedding model is bundled in the wheel. First run may download the spaCy language model (~13 MB). Subsequent runs complete in under 2 seconds for typical projects.

## License

[BUSL 1.1](LICENSE) — converts to Apache 2.0 three years after each release.
