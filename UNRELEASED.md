# Unreleased

### Added

- [core/payload]: New `core/payload.py` module producing a compact wire payload for HTTP transport. Reduces request body size on large projects.
- [core/funnel]: New `WIRE_MAX_BYTES_BY_TIER` table and `preflight_byte_size()` function. Local preflight returns a `payload_too_large` `FunnelError` before transmission instead of an opaque server-side 4xx.

### Changed

- [framework/rules]: Promoted `skill-name-matches-directory` to a cross-agent rule (CORE:S:0036). Skill `name` field must be kebab-case across every agent that loads `SKILL.md` entry points.
- [framework/rules]: Promoted `skill-no-readme` to a cross-agent rule (CORE:S:0035). Skill directories must keep all documentation in `SKILL.md` — a sibling `README.md` is never loaded.
- [framework/rules]: Promoted `skill-description-length` to a cross-agent rule (CORE:S:0040). The `description` field must be present in skill frontmatter; the open standard caps it at 1024 characters, with agent-specific caps acknowledged in the rule body.
- [framework/rules]: Promoted `import-depth-within-limit` to a cross-agent rule (CORE:S:0033) following the path-scope-declared supersede pattern. CORE carries a permissive absolute ceiling (max 10) as a sanity check; CLAUDE:S:0010 supersedes with Claude's documented 5-hop `@import` hard limit; CURSOR:S:0002 supersedes with `max: 1` reflecting Cursor's single-level `@filename` model. Codex and Copilot declare `CORE:S:0033` under `excludes:` in their `config.yml` because their instruction files do not honor `@<path>` syntax. Gemini inherits the CORE ceiling unchanged.
- [framework/rules/claude]: Renamed `memory-file-within-200-lines` to `memory-file-within-size-limit` (`CLAUDE:S:0011`) — slug no longer embeds the line number, since the threshold is fundamentally agent-defined. Stays in the CLAUDE namespace: Claude is the only agent with a dedicated `MEMORY.md` file the rule's `match: {type: memory}` can check (Gemini's memory is a section in `GEMINI.md`; Copilot's is system-managed with a 28-day TTL; Codex has none; Cursor's mechanic is undocumented). Promotion to CORE was reverted — it was forward-looking but in practice would have only fired on Claude.
- [framework/rules/claude]: Raised `rule-snippet-length` (`CLAUDE:S:0009`) threshold from 100 to 200 lines and dropped severity from `medium` to `low`. Added `see_also: [CORE:C:0044, CORE:S:0019]` cross-references — when a rule file follows topic-scatter and single-topic-per-section, 200 lines is comfortably enough.
- [framework/rules/copilot]: Renamed `applyto-scope-declared` to `path-scope-declared` for slug consistency with the cross-agent `path-scope-declared` family (Claude `paths:`, Cursor `globs:`, Copilot `applyTo:`). Rule body still describes Copilot's `applyTo:` mechanic; only the slug, title, and H1 heading change.
- [core/api_client]: `_lint_remote` now sends the compact wire format by default.

### Fixed

- [core/classification]: Cross-agent rules with `match: {type: scoped_rule}` and `match: {type: skill}` now fire correctly. Agent configs use plural keys (`rules:`, `skills:`) for human readability while rule-side match expressions use the singular concept names; without aliasing, those rules silently never matched any file. A `_FILE_TYPE_MATCH_ALIASES` map applied at `ClassifiedFile` construction normalizes the surface key to the match vocabulary while preserving the literal key for `surfaces.<agent>.<file_type>` lookup. Bandage solution — the proper fix is to align vocabulary in one direction (either agent configs use singular keys or rule-side `match.type` uses plural). Tracked as a follow-up.
- [core/agent_discovery]: `surfaces.<agent>.<file_type>.exclude` patterns now apply across every surface of the agent, not just the surface they were declared on. Two surfaces of the same agent commonly share patterns (e.g. `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`) — declaring an exclude on one previously left the file surfaced from the other. Discovery now collects the union of all per-surface excludes for the agent and applies it once per surface.
- [formatters/text/scorecard]: `compute_surface_scores` relativizes `ruleset_map.files[*].path` against the project root before classification. Absolute paths from the mapper were being tagged `nested` purely because their leading filesystem components inflated the `parts` count, so a project with one root-level `CLAUDE.md` was rendered as `Main (1) ... Nested (1)`. Findings (which already carry relative paths) and the mapper's file list now classify consistently.
- [interfaces/mcp]: Updated `explain` tool example coordinate from `CLAUDE:S:0011` (promoted/renamed) to `CLAUDE:S:0005` so the MCP tool description references a current rule.

### Removed
