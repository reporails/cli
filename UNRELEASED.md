# Unreleased

### Added

### Changed

### Fixed

- Check: the hint naming other agents' files appears only when a run is set to one agent and checks the whole project; a check of an empty folder keeps its usual message.

### Removed

### Internal

- The new agent-detection tests pass on a machine with no model files.
- The source type-checks for Windows again: the step that restricts the sign-in file's permissions is skipped where Windows has no such call.
- The smoke suite passes on a runner without the model files: JSON output is parsed from stdout alone, and the two multi-target scan-count tests are skipped without the model.
