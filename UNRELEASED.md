# Unreleased

### Added

### Changed

### Fixed

- Windows: files are classified, matched and reported with the same forward-slash paths as on macOS and Linux, so Cursor, Copilot, Antigravity and Codex files, skills and home-folder instructions are recognised there.
### Removed

### Internal

- Tests that rely on POSIX-only behaviour (interval timers, case-sensitive file names, symlinks, bash, the daemon socket) skip on Windows, and tests that write non-ASCII files or set a home directory no longer depend on the platform default encoding or the HOME variable.
