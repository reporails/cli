# Unreleased

### Added

### Changed

### Fixed

### Removed

### Internal
- Release tooling: `uv run poe release_gates` runs the release checks before a push and records the commit they passed on; pushing `main` or a version branch then goes through at once for that commit, and the push hook checks the branch being pushed instead of the one checked out.
