# Unreleased

### Added

### Changed

### Fixed

- Heal no longer rewrites settings, hook or MCP config files. Their findings stay in the check output and are listed for you to edit by hand.
- The check summary says "+1 more pair" instead of "+1 more pairs".

### Removed

### Internal

- A config file's findings keep their impact grade when heal lists them instead of rewriting them.
- Windows: the agent-scope test compares paths in the forward-slash form the product reports.
