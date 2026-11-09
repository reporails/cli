# Unreleased

### Added

### Changed

### Fixed

- On Windows, `ails xray --background` and the agent's `xray` tool open the page at once instead of reporting after 30 seconds that it did not start.
- On Windows, `ails check` names a file relative to its project, finds the files of a `~/.claude` folder and keeps a linked rule inside its project when the folder is spelled with a short (8.3) name; a file in the folder the command runs in is named with `/`, not its full path.

### Removed

### Internal

- The x-ray open scenarios run on Windows: the foreground-page step reads the printed address without `select`, and the file-name markup scenario is skipped there because Windows cannot hold such a file name.
