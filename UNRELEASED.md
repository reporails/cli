# Unreleased

### Added

### Changed

### Fixed

- [core/agent_discovery]: `surfaces.<agent>.<file_type>.exclude` patterns now apply across every surface of the agent, not just the surface they were declared on. Two surfaces of the same agent commonly share patterns (e.g. `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`) — declaring an exclude on one previously left the file surfaced from the other. Discovery now collects the union of all per-surface excludes for the agent and applies it once per surface.

### Removed
