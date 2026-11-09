# Unreleased

### Added

### Changed

### Fixed

- On Windows, `ails xray --background` and the agent's `xray` tool open the page at once instead of reporting after 30 seconds that it did not start.

### Removed

### Internal

- The x-ray open scenarios run on Windows: the foreground-page step reads the printed address without `select`, and the file-name markup scenario is skipped there because Windows cannot hold such a file name.
