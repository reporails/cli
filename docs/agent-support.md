---
title: "Agent Support"
description: "Which agents are recognized and what's covered"
version: "0.5.6"
last_updated: 2026-05-04
---

# Agent Support

Reporails recognizes the instruction-file conventions of five coding agents and runs the rules that match the files actually present in your repo. Each agent has its own root config plus optional rule / skill / sub-agent directories and (where the agent supports them) hook and MCP config files.

## Recognized agents

| Agent             | Root config                                           | Rule files (project)                                                 | Skills                                                  | Sub-agents                                                         | Other surfaces                                                         |
|-------------------|-------------------------------------------------------|----------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------------------------------|------------------------------------------------------------------------|
| Claude            | `CLAUDE.md` (+ optional `CLAUDE.local.md` override)   | `.claude/rules/**/*.md`                                              | `.claude/skills/**/SKILL.md`                            | `.claude/agents/**/*.md`                                           | commands, output-styles, memory, MCP, settings, hooks, scheduled tasks |
| Codex             | `AGENTS.md` (+ optional `AGENTS.override.md`)         | `.codex/rules/*.rules`                                               | `.agents/skills/**/SKILL.md`                            | `.codex/agents/*.toml`                                             | hooks, `.codex/config.toml`, skill metadata (`agents/openai.yaml`)     |
| Copilot (VS Code) | `.github/copilot-instructions.md` or `**/AGENTS.md`   | `.github/instructions/**/*.instructions.md`, `.claude/rules/**/*.md` | `.github/skills/`, `.claude/skills/`, `.agents/skills/` | `.github/agents/*.agent.md`                                        | hooks, prompts, MCP                                                    |
| Cursor            | `**/AGENTS.md` (`.cursorrules` recognized but legacy) | `.cursor/rules/**/*.mdc`, `.cursor/rules/**/*.md`                    | `.cursor/skills/`, `.claude/skills/`, `.codex/skills/`  | `.cursor/agents/*.md`, `.claude/agents/*.md`, `.codex/agents/*.md` | hooks, MCP, managed policy, bugbot rules                               |
| Gemini            | `GEMINI.md` or `**/AGENTS.md`                         | (no dedicated rules surface)                                         | `.gemini/skills/**/SKILL.md`                            | `.gemini/agents/*.md`                                              | commands, extensions, settings, hooks                                  |

Many agents intentionally read each other's directories — Cursor's skills column, for example, includes `.claude/skills/` and `.codex/skills/` because Cursor invokes skills regardless of which agent first authored them. The cells above show the most common project-level patterns; user-level and system-level patterns are also recognized — see [What gets scanned](#what-gets-scanned).

## How agent detection works

Reporails auto-detects which agents are present by checking for their marker files (Claude → `CLAUDE.md`, Codex → `AGENTS.md` plus a `.codex/` marker, Cursor → `.cursor/` directory, etc.). If your project has both `CLAUDE.md` and `.cursorrules`, both Claude and Cursor rule sets fire. If only one marker is present, only that agent's rules fire.

You can override detection with `--agent`:

```bash
ails check --agent claude    # only Claude-scoped rules
ails check --agent cursor    # only Cursor-scoped rules
```

Or pin a default in `.ails/config.yml`:

```yaml
default_agent: claude
```

## Multi-agent projects

When multiple agents share a base file (e.g., Codex, Cursor, and Gemini all read `AGENTS.md`), Reporails fires both the agent-specific rules *and* the cross-agent compatibility rules. Three CORE rules are specifically about cross-agent coexistence:

- `CORE:C:0026` Cross Agent Compatibility — flags directives that are correct for one agent but break another
- `CORE:C:0046` Same-Topic Reinforcement and Conflict — catches the same topic being reinforced or contradicted across agent files
- `CORE:S:0012` Agent Documents Filenames — checks that filenames match the agent's expected conventions

Disable any of these in your project config if your monorepo deliberately keeps agent-specific text in shared files — see [Configuration → Disabling rules](configuration.md#disabling-rules).

## What gets scanned

For every recognized agent, Reporails resolves files at three scopes:

- **Project** — files inside your repository (e.g., `CLAUDE.md`, `.claude/rules/**/*.md`)
- **User** — files in your home directory (`~/.claude/`, `~/.cursor/`, `~/.codex/`, etc.) that the agent itself loads at session start
- **System / managed** — platform-specific managed-config paths (`/etc/...`, `/Library/Application Support/...`, `C:/ProgramData/...`)

The user and system scopes are part of your instruction system because the agent reads them at session start regardless of which directory you launched from. If you keep sensitive content in `~/.claude/CLAUDE.md`, it is included in the analysis payload to the same degree as `CLAUDE.md` in your repo (see [FAQ → Is my instruction file ever stored](faq.md#is-my-instruction-file-ever-stored-on-the-diagnostic-backend) for what actually leaves your machine).

Hooks and settings written in JSON are validated against the documented schema for each agent — type fields, event-name casing, required keys. Mistakes that would silently fail (a misspelled `PreToolUse` event, a `prompt`-type hook in an agent that only supports `command`) are flagged.

## Cross-agent rules

A subset of rules apply regardless of which agent you use:

- File size limits (`CORE:E:0001`, `CORE:E:0002`)
- Heading hierarchy and structural integrity
- Reinforcement patterns ("must" / "never" / specific over generic)
- Credential and secret handling
- Cross-file consistency (`CORE:C:0026`, `CORE:C:0046`)
- Filename conventions (`CORE:S:0012`)
- ... and many more covering specificity, brevity, formatting, frontmatter integrity, and other dimensions — browse the full set at [reporails.com/rules](https://reporails.com/rules)

These rules carry the prefix `CORE:` and fire whenever any recognized instruction file exists, regardless of which agents are detected.

---

[← Getting Started](getting-started.md) · Agent Support · [Tiers and Limits →](tiers.md)
