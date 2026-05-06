# Unreleased

### Changed

- [framework/schemas]: Added `scope: nested` to the `agent.schema.yml` and `rule.schema.yml` enums. Captures surfaces whose subtree applicability comes from file LOCATION (subdirectory CLAUDE.md / AGENTS.md / GEMINI.md) rather than from in-file frontmatter. Replaces the previous overload of `scope: path_scoped` for these surfaces.

- [framework/rules]: Project root for `ails check <path>` is now `<path>` itself — no walking up. Files outside the targeted subtree are out of scope, regardless of `.git` or `.ails/backbone.yml` location. `engine_helpers._find_project_root` continues to walk up for cache key derivation only and now also recognizes IDE workspace markers (`.vscode/`, `.idea/`, `.github/`) as project-root signals.

### Fixed

- [src/reporails_cli/core]: Instruction-file discovery and classification now correctly distinguish `main` files at the user's target from `nested_context` / `child_instruction` files in subdirectories. Per-package CLAUDE.md / AGENTS.md / GEMINI.md files in monorepos are classified as `nested_context` rather than `main`, so size and other `match: {type: main}` rules no longer false-positive on per-package nested files. Fixes false-positive size errors when running `ails check` against monorepos.

- [src/reporails_cli/core/agent_discovery.py + core/agents.py]: Filename matching for agent instruction files is now case-sensitive, matching how Codex's source (`codex-rs/core/src/agents_md.rs` — `DEFAULT_AGENTS_MD_FILENAME = "AGENTS.md"`, `LOCAL_AGENTS_MD_FILENAME = "AGENTS.override.md"`) and the agents.md spec ("AGENTS.override.md, AGENTS.md, TEAM_GUIDE.md, .agents.md. Filenames not on this list are ignored for instruction discovery.") treat filename casing as authoritative. A file named `agents.md` (lowercase, no leading dot) is no longer falsely surfaced as a Codex AGENTS.md candidate.

- [src/reporails_cli/core/registry.py]: `depends_on` now resolves through supersession. When `CODEX:S:0003 supersedes CORE:S:0027`, rules that depend on `CORE:S:0027` (e.g., `CORE:S:0030`, `CORE:G:0006`) are satisfied by `CODEX:S:0003` instead of warning that the dependency is "not loaded". `_apply_supersession` now returns a `{superseded_id: successor_id}` map, and `_validate_depends_on` consults it before emitting the missing-dependency warning.

- [framework/rules]: Added `nested_context` declarations for codex / cursor / copilot / generic agents so per-package `**/AGENTS.md` files in monorepos are surfaced and validated under the agent's on-demand loading model rather than being skipped. Fixed `cursor.rules` (now `scope: path_scoped` to reflect frontmatter-based path filtering) and `cursor.bugbot_rules` (now `scope: global` since BugBot decides applicability).
