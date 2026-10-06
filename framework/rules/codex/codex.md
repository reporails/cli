---
last_verified: 2026-09-30
registry: framework/rules/codex/config.yml
---

# OpenAI Codex

## Surface inventory


| Surface                | Location                                                                                       | Format                                                 | Cardinality             | Purpose                                                                          |
|------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------|-------------------------|----------------------------------------------------------------------------------|
| Main instruction       | `AGENTS.md` (walked from project root to cwd)                                                  | Markdown                                               | Chain (concatenated)    | Project guidance, included in first turn                                         |
| Override instruction   | `AGENTS.override.md` (same walk; checked first at each directory)                              | Markdown                                               | Chain                   | Takes priority over AGENTS.md at each directory level                            |
| User instruction       | `~/.codex/AGENTS.md` or `~/.codex/AGENTS.override.md` (in `CODEX_HOME`)                        | Markdown                                               | Singleton               | Personal defaults                                                                |
| Fallback files         | Configurable via `project_doc_fallback_filenames` in `~/.codex/config.toml`                    | Markdown                                               | Chain                   | Additional filenames Codex tries when `AGENTS.md` is missing at a directory      |
| Skills                 | `.agents/skills/<name>/SKILL.md` (CWD), `../.agents/skills/<name>/SKILL.md` (parent), repo root | Markdown + YAML frontmatter                            | Hierarchical collection | Task-specific capabilities (3 project scopes)                                    |
| User skills            | `~/.agents/skills/<name>/SKILL.md`, `~/.codex/skills/<name>/SKILL.md`                          | Markdown + YAML frontmatter                            | Hierarchical collection | Personal cross-repo skills                                                       |
| Admin skills           | `/etc/codex/skills/<name>/SKILL.md` (Linux/macOS); Windows %ProgramData%\OpenAI\Codex\skills   | Markdown + YAML frontmatter                            | Hierarchical collection | Admin-provided default skills                                                    |
| System skills          | Bundled with Codex by OpenAI                                                                   | Markdown + YAML frontmatter                            | Hierarchical collection | Useful skills relevant to a broad audience                                       |
| Skill metadata         | `<skill>/agents/openai.yaml`                                                                   | YAML                                                   | Per-skill optional      | Display info (interface), policy (allow_implicit_invocation), MCP dependencies   |
| Project config         | `.codex/config.toml` (per-directory chain, project root → cwd, trusted projects only)          | TOML                                                   | Chain                   | Project-scoped settings (closest to cwd wins; trusted only)                      |
| User config            | `~/.codex/config.toml` (in `CODEX_HOME`, default `~/.codex`)                                   | TOML                                                   | Singleton               | Model, sandbox, approval, MCP, agents, hooks, fallback filenames                 |
| System managed config  | `managed_config.toml` (system/managed file)                                                    | TOML                                                   | Singleton               | System-managed defaults (referenced in layered config order)                     |
| System requirements    | `/etc/codex/requirements.toml` (Unix); `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows) | TOML                                                   | Singleton               | Admin-enforced constraints (approval policy, sandbox, MCP allowlist, hooks)      |
| macOS MDM              | macOS managed preferences (highest precedence in layered order)                                | mobileconfig                                           | Singleton               | Cloud/MDM-managed enterprise overrides                                           |
| Rules (project)        | `.codex/rules/*.rules`                                                                         | Starlark (`.rules`)                                    | Collection              | Command execution control via `prefix_rule()` — allow/prompt/forbidden decisions |
| Rules (user)           | `~/.codex/rules/*.rules`                                                                       | Starlark (`.rules`)                                    | Collection              | User-level command execution control                                             |
| Subagents              | `.codex/agents/<name>.toml`                                                                    | TOML (`name`, `description`, `developer_instructions`) | Collection              | Custom agent definitions with model/sandbox/MCP overrides                        |
| User subagents         | `~/.codex/agents/<name>.toml`                                                                  | TOML                                                   | Collection              | User-level subagent definitions                                                  |
| MCP servers            | `[mcp_servers.<id>]` in config.toml (user or project)                                          | TOML (STDIO/HTTP, OAuth, allowlists/blocklists)        | Collection              | Tool server definitions with OAuth support                                       |
| Apps                   | `[apps.<id>]` and `[apps._default]` in config.toml                                             | TOML (per-tool enablement, destructive/open-world)     | Collection              | ChatGPT Apps and connectors (per-tool overrides)                                 |
| Hooks (file)           | `~/.codex/hooks.json` (user), `<repo>/.codex/hooks.json` (project)                             | JSON                                                   | Singleton               | Standalone hooks file                                                            |
| Hooks (inline)         | `[hooks]` table inside `~/.codex/config.toml` or `<repo>/.codex/config.toml`                   | TOML                                                   | Singleton               | Inline hook definitions                                                          |
| Memory                 | `~/.codex/memories/` (`[features].memories`, `memories.*` config keys)                         | Opaque (generated state)                               | Collection              | Agent-written persistent memories; on-disk path not authoritatively documented   |
| Plugins                | Plugin marketplace via `/plugins` command (managed_plugin_uri in requirements.toml)            | (componentized)                                        | Collection              | Bundles skills, apps, MCP servers, hook definitions; remote install supported    |

**Discovery**: Codex walks from the project root to your current working directory, concatenating all `AGENTS.md` (and override + fallback) files until the byte cap (`project_doc_max_bytes`, 32 KiB default) is reached. Per-directory order: `AGENTS.override.md` → `AGENTS.md` → entries from `project_doc_fallback_filenames` (e.g. `TEAM_GUIDE.md`, `.agents.md`). At most one file per directory.

**Precedence**: Closer to cwd wins (appears later in the concatenated prompt). Layered config order (highest first): cloud-managed requirements (ChatGPT Business/Enterprise) → macOS MDM → `/etc/codex/requirements.toml` → `managed_config.toml` → `~/.codex/config.toml` → project `.codex/config.toml` chain. System layers cannot be overridden; lower layers can fill unset fields.

**Hooks**: Discovered next to active config layers. Two forms — standalone `hooks.json` files (`~/.codex/hooks.json`, `<repo>/.codex/hooks.json`) OR inline `[hooks]` tables inside `config.toml`. 12 events (re-verified 2026-09-30, expanded from 10): `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `Stop`, `Interrupt`. Handler types `command` and `mcp_tool` (`prompt`/`agent` are parsed but skipped). Requires `[features] codex_hooks = true` in config.toml.

**Plugins**: Componentized — each plugin can bundle skills, app mappings, MCP server configuration, presentation assets, and hooks. Managed via `/plugins` command. Marketplace support and remote install/uninstall added in 2026.

**Trust model**: Project-scoped layers (`.codex/config.toml`, project hooks, project rules, project agents, project MCP) load only when the project is trusted. Untrusted projects: Codex ignores all project `.codex/` layers.

**Note on `developer_instructions`**: Documented as a required field on per-subagent `.codex/agents/<name>.toml` files. The field name does not appear in the public `config-advanced` reference as a top-level config.toml key — earlier narratives may have conflated locations. Treat as subagent-only until/unless an authoritative source for top-level usage is found.


## Sources

- [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md) — Discovery walk, concatenation, override, byte cap, fallback filenames
- [Advanced Config](https://learn.chatgpt.com/docs/config-file/config-advanced) — config.toml, project trust, project chain, MCP, sandbox
- [Config Reference](https://learn.chatgpt.com/docs/config-file/config-reference) — Top-level keys: `apps`, `mcp_servers`, `hooks`, `project_doc_fallback_filenames`, `project_doc_max_bytes`, `[features]`
- [Config Basics](https://learn.chatgpt.com/docs/config-file/config-basic) — Layered config order, feature flags, `--enable feature_name`
- [Managed Configuration (Enterprise)](https://learn.chatgpt.com/docs/enterprise/managed-configuration) — `requirements.toml` paths (Unix and Windows), what it constrains, MDM precedence
- [Skills](https://learn.chatgpt.com/docs/build-skills) — SKILL.md spec, 6 discovery scopes (CWD, parent, repo root, user, admin, system bundled), `agents/openai.yaml` metadata
- [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules) — Starlark `.rules`, `prefix_rule(pattern, decision, justification)`, project + user paths
- [Hooks](https://learn.chatgpt.com/docs/hooks) — `hooks.json` and inline `[hooks]`, 12 events (incl. SessionEnd, PermissionRequest, PreCompact/PostCompact, SubagentStart/Stop, Interrupt), `command`/`mcp_tool` handlers, `codex_hooks` feature flag
- [Subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents) — TOML definitions, required `developer_instructions`, per-agent `model`/`sandbox_mode`/`mcp_servers` overrides
- [MCP](https://learn.chatgpt.com/docs/extend/mcp) — `[mcp_servers.<id>]` STDIO/HTTP, OAuth, project (trusted) and user scope
- [Automations (Desktop)](https://learn.chatgpt.com/docs/automations) — Sidebar-managed recurring tasks. On-disk path NOT in official docs as of audit date; patterns left empty.
- [Changelog](https://learn.chatgpt.com/docs/changelog) — 2026: hooks GA, plugin marketplace + remote install, MultiAgentV2 hints, `[features].memories`, automations

