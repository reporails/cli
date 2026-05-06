# Unreleased

### Added

### Changed

- [framework/rules]: Promoted `import-depth-within-limit` to a cross-agent rule (CORE:S:0033) following the path-scope-declared supersede pattern. CORE carries a permissive absolute ceiling (max 10) as a sanity check; CLAUDE:S:0010 supersedes with Claude's documented 5-hop `@import` hard limit; CURSOR:S:0002 supersedes with `max: 1` reflecting Cursor's single-level `@filename` model. Codex and Copilot declare `CORE:S:0033` under `excludes:` in their `config.yml` because their instruction files do not honor `@<path>` syntax. Gemini inherits the CORE ceiling unchanged.

### Fixed

### Removed
