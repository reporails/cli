# Unreleased

### Added

### Changed

### Fixed

- `ails xray`: a hook that ran without adding text to the context, such as a Stop hook, counts as fired in the Hooks group instead of not loaded.

### Removed

### Internal

- Tests: the nested-file project-config scenario gets findings with no model on disk.
- Tests: the x-ray session and server tests run on Windows.
- Tests: the architecture, file-mode, x-ray page record and synced-skills tests run on Windows.
- Tests: the integration, behave and smoke suites run on Windows.
