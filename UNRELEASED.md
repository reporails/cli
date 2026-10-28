# Unreleased

### Added

### Changed

### Fixed

- A `heal_exclude` entry that is a bare file name now matches only at the project root, as documented, and the findings listed as `excluded` name the files they sit in.

### Removed

### Internal

- Tests: a property suite runs the real `ails` and the MCP server over a fixture set in text, JSON, `github` and MCP, and checks on every run that a disabled rule appears in no output, the total equals m_probe + client + server, every format carries one finding set, and the exit code matches the findings; the mutation probe accepts an upper-tier killing command.
