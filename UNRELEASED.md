# Unreleased

### Added

### Changed

### Fixed

- mcp: capped the `mcp` dependency below 2. `reporails-mcp` crashed on startup on fresh installs with `AttributeError: 'Server' object has no attribute 'list_tools'`, because the unbounded `mcp>=1.0.0` requirement resolved to mcp 2.x, which removed the decorator API that `interfaces/mcp/server.py` uses.

### Removed
