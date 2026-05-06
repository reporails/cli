# Unreleased

### Changed

- [framework/schemas]: Added `scope: nested` to the `agent.schema.yml` and `rule.schema.yml` enums. Captures surfaces whose subtree applicability comes from file LOCATION (subdirectory CLAUDE.md / AGENTS.md / GEMINI.md) rather than from in-file frontmatter. Replaces the previous overload of `scope: path_scoped` for these surfaces.

- [framework/rules]: Project root for `ails check <path>` is now `<path>` itself — no walking up. Files outside the targeted subtree are out of scope, regardless of `.git` or `.ails/backbone.yml` location. `engine_helpers._find_project_root` continues to walk up for cache key derivation only and now also recognizes IDE workspace markers (`.vscode/`, `.idea/`, `.github/`) as project-root signals.

### Fixed

- [src/reporails_cli/core]: Instruction-file discovery and classification now correctly distinguish `main` files at the user's target from `nested_context` / `child_instruction` files in subdirectories. Per-package CLAUDE.md / AGENTS.md / GEMINI.md files in monorepos are classified as `nested_context` rather than `main`, so size and other `match: {type: main}` rules no longer false-positive on per-package nested files. Fixes false-positive size errors when running `ails check` against monorepos.

- [src/reporails_cli/core/agent_discovery.py + core/agents.py]: Filename matching for agent instruction files is now case-sensitive, matching how Codex's source (`codex-rs/core/src/agents_md.rs` — `DEFAULT_AGENTS_MD_FILENAME = "AGENTS.md"`, `LOCAL_AGENTS_MD_FILENAME = "AGENTS.override.md"`) and the agents.md spec ("AGENTS.override.md, AGENTS.md, TEAM_GUIDE.md, .agents.md. Filenames not on this list are ignored for instruction discovery.") treat filename casing as authoritative. A file named `agents.md` (lowercase, no leading dot) is no longer falsely surfaced as a Codex AGENTS.md candidate.

- [src/reporails_cli/core/registry.py]: `depends_on` now resolves through supersession. When `CODEX:S:0003 supersedes CORE:S:0027`, rules that depend on `CORE:S:0027` (e.g., `CORE:S:0030`, `CORE:G:0006`) are satisfied by `CODEX:S:0003` instead of warning that the dependency is "not loaded". `_apply_supersession` now returns a `{superseded_id: successor_id}` map, and `_validate_depends_on` consults it before emitting the missing-dependency warning.

- [framework/rules]: Added `nested_context` declarations for codex / cursor / copilot / generic agents so per-package `**/AGENTS.md` files in monorepos are surfaced and validated under the agent's on-demand loading model rather than being skipped. Fixed `cursor.rules` (now `scope: path_scoped` to reflect frontmatter-based path filtering) and `cursor.bugbot_rules` (now `scope: global` since BugBot decides applicability).

### Added

- [framework/schemas/project.schema.yml]: New `surfaces` and `agents` keys for `.ails/config.yml`. `surfaces.<agent>.<file_type>.include` / `.exclude` adjusts which globs each agent surface scans without modifying bundled configs. `agents.<id>.fallback_filenames` mirrors Codex `project_doc_fallback_filenames` so per-project alternative instruction filenames (e.g. `TEAM_GUIDE.md`) are picked up by the validator.

- [src/reporails_cli/core/config.py]: `.ails/config.local.yml` (gitignored) now layers on top of the committed `.ails/config.yml` for personal/CI-specific overrides — object keys merge recursively, array keys extend, scalar keys are replaced.

- [src/reporails_cli/interfaces/cli/config_command.py]: `ails config set` now writes `.ails/.gitignore` listing `.gitignore` itself and `config.local.yml` whenever `.ails/config.yml` is created/updated, so layered local config stays out of version control by default.

- [src/reporails_cli/formatters/text]: The text formatter's surface classifier now distinguishes `main` (root-level instruction file) from `nested` (subdirectory copies). The scorecard and group renderer show a separate "Nested" section; nested file paths display the full relative path (`packages/web/CLAUDE.md`) rather than just `parent/CLAUDE.md` so users can locate the file.

- [tests/unit/test_scan_scope.py]: `test_codex_fallback_filenames_surface` now creates `.codex/config.toml` in the fixture so codex passes the codex/generic disambiguation deterministically. Without the marker, the test was HOME-dependent: locally a `~/.codex/` user dir let codex through, but a fresh CI runner without `~/.codex/` dropped codex and the fallback patterns never fired.

- [src/reporails_cli/core/classification.py]: `_location_matches_mode` now distinguishes "loose" leaf patterns (`**/CLAUDE.md`, bare `CLAUDE.md`) from "tight" path-prefixed patterns (`.github/copilot-instructions.md`). Path-prefixed patterns already constrain location via the prefix itself, so the ancestor-chain check is skipped — fixes false-negative classification of Copilot's `.github/copilot-instructions.md` (its parent `.github/` is not in the project-root ancestor chain, but the file is the one and only valid copilot main).
