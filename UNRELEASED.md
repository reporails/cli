# Unreleased

### Added

### Changed

### Fixed

### Removed

### Internal

- The MCP server asks again when a new sign-in is still reaching the server instead of remembering that reply, and heal does not read that reply as no account.
- The API key, the upgrade link and the server's retry wait are each read in one place.
