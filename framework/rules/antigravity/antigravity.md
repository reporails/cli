---
last_verified: 2026-09-03
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
| Nested context         | `<subdir>/AGENTS.md`, `<subdir>/GEMINI.md`                         | Markdown                                | Hierarchical | On-demand subtree instructions                                                     |
| Skills (go-forward)    | `.agents/skills/<name>/SKILL.md`                                    | Markdown + YAML frontmatter             | Hierarchical | Agent Skills; `.gemini/skills/` must be relocated here to be recognized           |
| Skills (legacy)        | `.gemini/skills/<name>/SKILL.md`                                    | Markdown + YAML frontmatter             | Hierarchical | Legacy skills location                                                             |
| User skills            | `~/.agents/skills/`, `~/.gemini/antigravity-cli/skills/`            | Markdown + YAML frontmatter             | Hierarchical | Personal cross-project skills                                                      |
| Subagents              | `.agents/agents/*.md`, `.gemini/agents/*.md`                        | Markdown + YAML frontmatter             | Collection   | Reusable agent definitions (code-reviewer, security-auditor, test-engineer, @name) |
| Settings               | `.gemini/settings.json`, `.gemini/settings.toml`                    | JSON / TOML                             | Singleton    | Project config, hooks, policies                                                    |
| User state             | `~/.gemini/antigravity/` (`conversations/`, `brain/`, `global_workflows/`) | Mixed                           | Collection   | Antigravity private state and memory                                              |
| Custom commands        | `.gemini/commands/*.toml`                                           | TOML (`{{args}}`, `!{shell}`, `@{file}`)| Collection   | Slash-command prompt templates                                                     |
| Hooks                  | `.gemini/settings.json` `hooks` key                                | JSON                                    | Collection   | Lifecycle event hooks (kept from Gemini CLI; wire format inherited — see below)    |
| MCP config             | `.agents/mcp_config.json`, `~/.gemini/antigravity/mcp_config.json`  | JSON                                    | Collection   | Dedicated lightweight MCP server profile (separated from primary settings)         |
| Plugins (Extensions)   | `~/.gemini/antigravity-cli/plugins/`, `.gemini/extensions/`         | JSON / Code                             | Collection   | Plugin bundles (Gemini "Extensions" are now Antigravity "plugins")                 |
| System prompt override | `.gemini/system-prompt.md`                                          | Markdown                                | Singleton    | Replace default system prompt                                                      |
| Geminiignore           | `.geminiignore`                                                     | gitignore syntax                        | Singleton    | Exclude files from tool operations                                                 |
| Enterprise policy      | Google Cloud admin / Code Assist Enterprise                         | Managed                                 | Collection   | Org-enforced policies                                                              |
| System overrides       | `/etc/gemini-cli/settings.json` (Linux), `/Library/Application Support/GeminiCli/settings.json` (macOS) | JSON | Singleton | Managed system overrides                                            |

**Discovery**: AGENTS.md + GEMINI.md hierarchical from `~/` > project root > subdirectories (on-demand on navigation). Skills discovered from `.agents/skills/` (go-forward), `.gemini/skills/` (legacy), and `~/.gemini/antigravity-cli/skills/`. Antigravity stores conversations, memory (`brain/`), and global workflows under `~/.gemini/antigravity/`.

**Precedence**: nested > project > user. Enterprise / system policies override all.

**Backward-compat**: Antigravity keeps reading `GEMINI.md` and `~/.gemini/GEMINI.md`, so existing Gemini-CLI instruction files continue to validate under this agent. The `gemini` agent slug was retired into `antigravity` on 2026-06-21 (no separate 6th pack).

**Hooks — UNCONFIRMED format**: Google's blog confirms Antigravity keeps Hooks, but `antigravity.google/docs` is JS-rendered and not machine-fetchable, so the exact wire format is unverified. The `hooks` file_type and the 3 `ANTIGRAVITY:S:*` hook rules inherit the Gemini-CLI `.gemini/settings.json` `hooks` shape (11 events: SessionStart, SessionEnd, BeforeAgent, AfterAgent, BeforeModel, AfterModel, BeforeToolSelection, BeforeTool, AfterTool, PreCompress, Notification) pending accessible Antigravity hook docs.

## Sources

- [Transitioning Gemini CLI to Antigravity CLI](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/) — shutdown 2026-06-18, kept features: Agent Skills, Hooks, Subagents, Extensions→plugins
- [Migrating from Gemini CLI](https://antigravity.google/docs/gcli-migration) — AGENTS.md + GEMINI.md rules, ~/.gemini/GEMINI.md global, .agents/skills relocation, mcp_config.json
- [Antigravity CLI Overview](https://antigravity.google/docs/cli-overview) — config under .gemini/, ~/.gemini/antigravity/ state dirs
- [gemini-cli#16058](https://github.com/google-gemini/gemini-cli/issues/16058) — Antigravity + Gemini CLI both write ~/.gemini/GEMINI.md (shared global path)
