# Unreleased

### Added

### Changed

### Fixed

### Removed

### Internal

- Every unit test added in this release carries its subsystem marker on the test itself.
- The faster first check keeps memory use flat on very large projects, sees files created between checks in a long-running MCP server, works with a relative project root, and reports a looping symlink once per walk; the new batching has model-free unit tests.
