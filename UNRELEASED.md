# Unreleased

### Added

### Changed

- Check: when a project is too large for the server to score in one request, the message says so and suggests checking a smaller part, instead of asking for a bug report.

### Fixed

- Check: a run pinned to one agent that finds none of its files now names the other agents the project has files for and how to check them, instead of asking for that agent's file.

### Removed

### Internal

- tests: the two-agent check test follows the rule runner's current call signature, so it runs again wherever the models are installed
- Heal smoke tests use a fixture whose bold constraint still gets a mechanical fix (a bold negation phrase or a list item is left as written).
