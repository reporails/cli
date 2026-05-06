# Unreleased

### Added

### Changed

### Fixed

- [core/classification]: Cross-agent rules with `match: {type: scoped_rule}` and `match: {type: skill}` now fire correctly. Agent configs use plural keys (`rules:`, `skills:`) for human readability while rule-side match expressions use the singular concept names; without aliasing, those rules silently never matched any file. A `_FILE_TYPE_MATCH_ALIASES` map applied at `ClassifiedFile` construction normalizes the surface key to the match vocabulary while preserving the literal key for `surfaces.<agent>.<file_type>` lookup. Bandage solution — the proper fix is to align vocabulary in one direction (either agent configs use singular keys or rule-side `match.type` uses plural). Tracked as a follow-up.

### Removed
