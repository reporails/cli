---
title: "Agent Support"
description: "Which agents are recognized and what's covered"
version: "0.6.0"
last_updated: 2026-09-18
---

# Agent Support

Reporails recognizes the instruction-file conventions of five coding agents and runs the rules that match the files actually present in your repo. Each agent has its own root config plus optional rule / skill / sub-agent directories and (where the agent supports them) hook and MCP config files.

## Recognized agents

| Agent             | Root config                                           | Rule files (project)                                                 | Skills                                                  | Sub-agents                                                         | Other surfaces                                                         |
|-------------------|-------------------------------------------------------|----------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------------------------------|------------------------------------------------------------------------|
| Claude            | `CLAUDE.md` (+ optional `CLAUDE.local.md` override)   | `.claude/rules/**/*.md` (also in subfolders)                         | `.claude/skills/**/SKILL.md` (also in subfolders)       | `.claude/agents/**/*.md` (also in subfolders)                      | commands, output-styles, memory, MCP, settings, hooks, scheduled tasks |
| Codex             | `AGENTS.md` (+ optional `AGENTS.override.md`)         | `.codex/rules/*.rules`                                               | `.agents/skills/**/SKILL.md` (also in subfolders)       | `.codex/agents/*.toml`                                             | hooks, `.codex/config.toml`, skill metadata (`agents/openai.yaml`), output persona (`personality`), scheduled tasks |
| Copilot (VS Code) | `.github/copilot-instructions.md` or `**/AGENTS.md`   | `.github/instructions/**/*.instructions.md`, `.claude/rules/**/*.md` | `.github/skills/`, `.claude/skills/`, `.agents/skills/` | `.github/agents/*.md`, `.claude/agents/*.md`                       | hooks, prompts, MCP                                                    |
| Cursor            | `**/AGENTS.md` (`.cursorrules` recognized but legacy) | `.cursor/rules/**/*.mdc` (a plain `.md` there is ignored by Cursor) | `.cursor/skills/`, `.agents/skills/` (both also in subfolders), `.claude/skills/`, `.codex/skills/` | `.cursor/agents/*.md`, `.claude/agents/*.md`, `.codex/agents/*.md` | hooks, MCP, managed policy, bugbot rules (`BUGBOT.md`, also in subfolders)                             |
| Antigravity       | `GEMINI.md` or `**/AGENTS.md`                         | `.agents/rules/*.md` (also in subfolders)                            | `.agents/skills/**/SKILL.md`                            | `.agents/agents/*.md`, `.gemini/agents/*.md`                       | commands, extensions, settings, hooks, memory (section inside `~/.gemini/GEMINI.md`), MCP, system_prompt, geminiignore, scheduled tasks (`/schedule`) |

Many agents intentionally read each other's directories — Cursor's skills column, for example, includes `.claude/skills/` and `.codex/skills/` because Cursor invokes skills regardless of which agent first authored them. The cells above show the most common project-level patterns; user-level and system-level patterns are also recognized — see [What gets scanned](#what-gets-scanned).

A skill's supporting markdown files (`reference.md`, `examples/*.md`, anything below the skill's folder) are discovered and checked together with its `SKILL.md`; scripts and data files are not.

## Plugin support

Recognition (above) is what `ails check` **scans**. The reporails **plugin** is how each agent **runs** the remedy loop: it delivers the `ails` skill and the reporails MCP server as a portable [Agent Plugins](https://agent-plugins.org) package. Agents that consume the portable form need no wrapper; the rest carry a thin native manifest. Installing the plugin registers the MCP server (`validate` / `remedy_brief` / `preflight` / `explain`) and loads the `ails` skill — one skill, maintained once, across all five.

Install it in your agent:

| Agent | Install |
|-------|---------|
| Claude Code | `/plugin marketplace add reporails/plugin`, then `/plugin install reporails@reporails` |
| Codex | `codex plugin marketplace add reporails/plugin`, then `codex plugin add reporails@reporails` |
| Cursor | `git clone https://github.com/reporails/plugin`, copy `plugin/plugins/reporails/` into `~/.cursor/plugins/local/reporails/`, restart Cursor |
| GitHub Copilot (VS Code) | `git clone https://github.com/reporails/plugin`, then "Install Plugin From Source" and pick the `plugin/plugins/reporails/` folder |
| Antigravity | `git clone https://github.com/reporails/plugin`, then `agy plugin install plugin/plugins/reporails` |

`ails install` runs the Claude Code and Codex steps and prints the rest; `ails install --project` installs for the current repository only, shared with collaborators (Claude Code; Codex installs for your user). `ails update` refreshes the plugin in each agent that has it. The plugin needs [`uv`](https://docs.astral.sh/uv/) on the machine: its first start downloads the CLI and the analysis model files (~275 MB, once per machine), so that first start needs network access.

On a large project Codex can time out the first `validate` call or the server's first start: raise `startup_timeout_sec` (default 10 s) and `tool_timeout_sec` (default 60 s) under `[mcp_servers.reporails]` in `~/.codex/config.toml`, for example `tool_timeout_sec = 300`.

## How agent detection works

Reporails detects an agent only from a clue that points at that agent: its own folder (`.claude/`, `.cursor/`, `.codex/`, `.github/`, `.gemini/`), a root file name no other agent uses (`CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `AGENTS.override.md`), or the project's own config naming it (`agents.codex.fallback_filenames` names Codex). Names several agents share (`AGENTS.md`) and editor folders (`.vscode/settings.json`) are no clue: a project with only those stays generic, runs the rules every agent shares, and the scorecard says the agent was not determined. Marker filenames are matched case-insensitively, so a lowercase `claude.md` is detected the same as the canonical casing. If your project has both `CLAUDE.md` and `.cursorrules`, both Claude and Cursor rule sets fire. If only one clue is present, only that agent's rules fire.

Name the agent yourself with `--agent <name>` or `ails config set default_agent <name>` when detection cannot tell.

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

When multiple agents share a base file (e.g., Codex, Cursor, and Antigravity all read `AGENTS.md`), Reporails fires both the agent-specific rules *and* the cross-agent compatibility rules. Three CORE rules are specifically about cross-agent coexistence:

- `CORE:C:0026` Cross Agent Compatibility — flags a shared instruction file that names one agent's files (such as `.cursorrules` or `CLAUDE.md`)
- `CORE:C:0046` Same-Topic Reinforcement and Conflict — catches the same topic being reinforced or contradicted across agent files
- `CORE:S:0012` Agent Documents Filenames — checks that filenames match the agent's expected conventions

Disable any of these in your project config if your monorepo deliberately keeps agent-specific text in shared files — see [Configuration → Disabling rules](configuration.md#disabling-rules).

## What gets scanned

For every recognized agent, Reporails resolves files at three scopes:

- **Project** — files inside your repository (e.g., `CLAUDE.md`, `.claude/rules/**/*.md`)
- **User** — files in your home directory (`~/.claude/`, `~/.cursor/`, `~/.codex/`, etc.) that the agent itself loads at session start
- **System / managed** — platform-specific managed-config paths (`/etc/...`, `/Library/Application Support/...`, `C:/ProgramData/...`, `C:/Program Files/ClaudeCode/` for Claude's managed settings)

The user and system scopes are part of your instruction system because the agent reads them at session start regardless of which directory you launched from. If you keep sensitive content in `~/.claude/CLAUDE.md`, it is included in the analysis payload to the same degree as `CLAUDE.md` in your repo (see [FAQ → Is my instruction file ever stored](faq.md#is-my-instruction-file-ever-stored-on-the-diagnostic-backend) for what actually leaves your machine).

Hooks and settings written in JSON are validated against the documented schema for each agent — type fields, event-name casing, required keys. Mistakes that would silently fail (a misspelled `PreToolUse` event, a `prompt`-type hook in an agent that only supports `command`) are flagged on a plain whole-project run, which checks each agent's hook, permission, MCP and plugin config files alongside its instruction files. A config file that declares no hooks draws no hook findings. You can also point `ails check` at one config file or capability directly (for example `ails check .claude/settings.json` or `ails check hooks --agent copilot`).

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
