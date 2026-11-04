---
last_verified: 2026-10-29
registry: framework/rules/antigravity/config.yml
---

# Google Antigravity CLI

Antigravity CLI is Google's successor to the Gemini CLI: Google retired the
open-source `gemini` CLI binary and the Gemini Code Assist IDE extensions on
2026-06-18 (transition blog, same date) and replaced them with Antigravity.
Antigravity reads the Gemini instruction surfaces for backward-compat — project
`GEMINI.md` and global `~/.gemini/GEMINI.md` — and promotes `AGENTS.md` as the
go-forward cross-agent primary. Its own state lives under `~/.gemini/antigravity/`.

## Surface inventory

| Surface                | Location                                                            | Format                                  | Cardinality  | Purpose                                                                            |
|------------------------|--------------------------------------------------------------------|-----------------------------------------|--------------|-----------------------------------------------------------------------------------|
| Project context (primary) | `<project-root>/AGENTS.md`                                       | Markdown                                | Singleton    | Go-forward cross-agent project rules (Antigravity's recommended primary)          |
| Project context (legacy)  | `<project-root>/GEMINI.md`                                       | Markdown                                | Singleton    | Backward-compat project rules (Antigravity still reads GEMINI.md)                  |
| Global context         | `~/.gemini/GEMINI.md`                                               | Markdown                                | Singleton    | Global user rules (Antigravity hardcodes its global rules to this shared path)     |
| Rules                  | `.agents/rules/*.md` (legacy `.agent/rules/*.md`), `<dir>/.agents/AGENTS.md`, `<dir>/.agents/GEMINI.md`, `~/.gemini/config/rules/*.md`, `~/.gemini/antigravity-cli/rules/*.md`, plugin `rules/`; `.agents/rules.json` config | Markdown + frontmatter `trigger` | Collection | Triggered rules per docs/rules |
| Nested context         | `<subdir>/AGENTS.md`, `<subdir>/GEMINI.md`                         | Markdown                                | Hierarchical | On-demand subtree instructions                                                     |
| Skills (go-forward)    | `.agents/skills/<name>/SKILL.md`                                    | Markdown + YAML frontmatter             | Hierarchical | Agent Skills; `.gemini/skills/` must be relocated here to be recognized           |
| Skills (legacy)        | `.gemini/skills/<name>/SKILL.md`                                    | Markdown + YAML frontmatter             | Hierarchical | Legacy skills location                                                             |
| User skills            | `~/.agents/skills/`, `~/.gemini/antigravity-cli/skills/`            | Markdown + YAML frontmatter             | Hierarchical | Personal cross-project skills                                                      |
| Subagents              | `.agents/agents/*.md`, `.gemini/agents/*.md`                        | Markdown + YAML frontmatter             | Collection   | Reusable agent definitions (code-reviewer, security-auditor, test-engineer, @name) |
| Settings               | `~/.gemini/antigravity-cli/settings.json` (docs); `.gemini/settings.json`, `.gemini/settings.toml` (unverified: not in docs as of 2026-10-29) | JSON / TOML | Singleton | CLI preferences; settings no longer hold hooks ("the CLI keeps a `hooks` key there but never loads it") |
| User state (unverified: not in docs as of 2026-10-29) | `~/.gemini/antigravity/` (`conversations/`, `brain/`, `global_workflows/`) | Mixed                           | Collection   | Antigravity private state and memory                                              |
| Custom commands (unverified: not in docs as of 2026-10-29) | `.gemini/commands/*.toml`                                           | TOML (`{{args}}`, `!{shell}`, `@{file}`)| Collection   | Slash-command prompt templates                                                     |
| Hooks                  | `.agents/hooks.json`, `~/.gemini/config/hooks.json`                | JSON                                    | Collection   | Lifecycle event hooks (dedicated `hooks.json`; see below)                          |
| MCP config             | `.agents/mcp_config.json`, `~/.gemini/config/mcp_config.json` (legacy/unverified: `~/.gemini/antigravity/mcp_config.json`) | JSON                                    | Collection   | Dedicated lightweight MCP server profile; remote URL key is `serverUrl` (`url`/`httpUrl` legacy) |
| Plugins (Extensions)   | `~/.gemini/antigravity-cli/plugins/`, `.gemini/extensions/`         | JSON / Code                             | Collection   | Plugin bundles (Gemini "Extensions" are now Antigravity "plugins")                 |
| System prompt override (unverified: not in docs as of 2026-10-29) | `.gemini/system-prompt.md`                                          | Markdown                                | Singleton    | Replace default system prompt                                                      |
| Geminiignore (unverified: not in docs as of 2026-10-29) | `.geminiignore`                                                     | gitignore syntax                        | Singleton    | Exclude files from tool operations                                                 |
| Enterprise policy (unverified: no policy file paths in docs as of 2026-10-29) | Google Cloud admin / Code Assist Enterprise                         | Managed                                 | Collection   | Org-enforced policies                                                              |
| System overrides (unverified: not in docs as of 2026-10-29) | `/etc/gemini-cli/settings.json` (Linux), `/Library/Application Support/GeminiCli/settings.json` (macOS) | JSON | Singleton | Managed system overrides                                            |

**Discovery**: AGENTS.md + GEMINI.md hierarchical from `~/` > project root > subdirectories (on-demand on navigation). Skills discovered from `.agents/skills/` (go-forward), `.gemini/skills/` (legacy), and `~/.gemini/antigravity-cli/skills/`. Antigravity stores conversations, memory (`brain/`), and global workflows under `~/.gemini/antigravity/`.

**Precedence**: nested > project > user. Enterprise / system policies override all.

**Backward-compat**: Antigravity keeps reading `GEMINI.md` and `~/.gemini/GEMINI.md`, so existing Gemini-CLI instruction files continue to validate under this agent. The `gemini` agent slug was retired into `antigravity` on 2026-06-21 (no separate 6th pack).

**Hooks**: a dedicated `hooks.json` — project `.agents/hooks.json`, global `~/.gemini/config/hooks.json`, or an installed plugin's own `hooks.json` — not the Gemini-CLI `.gemini/settings.json` `hooks` key. 6 events (re-verified 2026-10-28 against [the hooks reference](https://antigravity.google/docs/hooks/)): `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`. Handler `type` is optional and defaults to `command`, the only supported type; `command` is required. The 3 `ANTIGRAVITY:S:*` hook rules check this shape.

## Sources

- [Transitioning Gemini CLI to Antigravity CLI](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/) — shutdown 2026-06-18, kept features: Agent Skills, Hooks, Subagents, Extensions→plugins
- [Migrating from Gemini CLI](https://antigravity.google/docs/cli/gcli-migration) — AGENTS.md + GEMINI.md rules, ~/.gemini/GEMINI.md global, .agents/skills relocation, mcp_config.json
- [Antigravity CLI Overview](https://antigravity.google/docs/overview?tab=cli) — names no config paths (re-checked 2026-10-29)
- [Hooks](https://antigravity.google/docs/hooks/) — hooks.json, 6 events
- [Settings](https://antigravity.google/docs/settings?tab=cli) — ~/.gemini/antigravity-cli/settings.json, keybindings.json, config/hooks.json, config/mcp_config.json, plugins
- [Rules](https://antigravity.google/docs/rules) — AGENTS.md/GEMINI.md, .agents/rules, global and plugin rules
- [Plugins](https://antigravity.google/docs/plugins) — plugin layout and install locations
- [Enterprise](https://antigravity.google/docs/enterprise) — ~/.gemini/config/config.json (enableAdc); no policy file paths
- [gemini-cli#16058](https://github.com/google-gemini/gemini-cli/issues/16058) — Antigravity + Gemini CLI both write ~/.gemini/GEMINI.md (shared global path)
