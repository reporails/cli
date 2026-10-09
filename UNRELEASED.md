# Unreleased

### Added

### Changed

### Fixed

- MCP: checking a single file during heal no longer reports a whole-file finding (such as missing headings) that the file does not draw in your project, so the remedy agent is not asked to add it.

### Removed

### Internal

- Tests: the MCP, single-file and host-hook tests check the 0.6.2 behavior and no longer depend on the machine's home folder or sign-in.
