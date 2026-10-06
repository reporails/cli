# Unreleased

### Added

### Changed

- `ails update` also says how to update the reporails plugin in Cursor, GitHub Copilot and Antigravity, which install it by hand.
- Account messages also appear as annotations in `--format github` and in the `--heal` JSON output.

### Fixed

### Removed

### Internal

- The MCP server asks again when a new sign-in is still reaching the server instead of remembering that reply, and heal does not read that reply as no account.
- The API key, the upgrade link and the server's retry wait are each read in one place.
- The plugin's server starts this release or a newer one in its line.
