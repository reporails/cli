# Unreleased

### Added

### Changed

### Fixed

- auth: `ails auth login` now identifies an upstream edge challenge (e.g. a Cloudflare interstitial in front of the auth endpoint) as the real cause instead of reporting a generic HTTP error or a misleading "OAuth not configured" message. Both the client-id lookup and the token-exchange step recognize the challenge page and tell you it is not fixable in the CLI — retry shortly or contact support.

### Removed
