# Reporails CLI

AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 97 rules.

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
Reporails — Diagnostics — Pro (beta)

  ┌─ Main (1)
  │ CLAUDE.md
  │   ⚠       Missing directory layout — show the project …  CORE:C:0035
  │   ⚠ L9    7 of 7 instruction(s) lack effective reinfor…  CORE:C:0053
  │     ... and 16 more
  │     1 misordered · 1 orphan · 1 ambiguous
  │
  └─ 21 findings

  ── Summary ────────────────────────────────────────────────────────

  Score: 7.9 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░  (1.3s)
  Agent: Claude

  Scope:
    capabilities: 2 main
    instructions: 4 directive / 7 prose (50%)
                  3 constraint

  21 findings · 4 warnings · 1 info
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

97 rules across five categories:

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
