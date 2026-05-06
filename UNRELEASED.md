# Unreleased

### Added

### Changed

### Fixed

- [core/agent_discovery]: `surfaces.<agent>.<file_type>.exclude` patterns now apply across every surface of the agent, not just the surface they were declared on. Two surfaces of the same agent commonly share patterns (e.g. `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`) — declaring an exclude on one previously left the file surfaced from the other. Discovery now collects the union of all per-surface excludes for the agent and applies it once per surface.
- [formatters/text/scorecard]: `compute_surface_scores` relativizes `ruleset_map.files[*].path` against the project root before classification. Absolute paths from the mapper were being tagged `nested` purely because their leading filesystem components inflated the `parts` count, so a project with one root-level `CLAUDE.md` was rendered as `Main (1) ... Nested (1)`. Findings (which already carry relative paths) and the mapper's file list now classify consistently.

### Removed
