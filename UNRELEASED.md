# Unreleased

### Added

### Changed

### Fixed

- Check: in `--format json` and the MCP `validate` reply, the counts of findings by source (`stats.m_probe_count`, `stats.client_check_count`, `stats.server_diagnostic_count`) no longer count a finding the run leaves out: one whose rule is disabled, silenced with `ails-disable-line`, or does not apply to that kind of file.

### Removed

### Internal
