# Unreleased

### Added

### Changed

### Fixed

### Removed

### Internal

- Tests that rely on POSIX-only behaviour (interval timers, case-sensitive file names, symlinks, bash, the daemon socket) skip on Windows, and tests that write non-ASCII files or set a home directory no longer depend on the platform default encoding or the HOME variable.
