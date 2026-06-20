# Unreleased

### Added

- testing: added internal regression coverage to keep `ails check` output stable across refactors.
- testing: added an architecture check that keeps error handling at the network boundary consistent, so faults surface clearly instead of being silently swallowed.
- testing: opt-in live-network lane exercising the `ails auth login` activation path so first-contact auth regressions surface in CI rather than at a new user.

### Changed

### Fixed

- auth: clearer errors when the credentials or config file can't be read — a corrupt file now produces a visible warning and the session continues with anonymous access, instead of a silent tier downgrade.
- performance: `ails check` is substantially faster on large projects, with identical output.
- auth: `ails auth login` now identifies an upstream edge challenge (e.g. a Cloudflare interstitial in front of the auth endpoint) as the real cause instead of reporting a generic HTTP error or a misleading "OAuth not configured" message. Both the client-id lookup and the token-exchange step recognize the challenge page and tell you it is not fixable in the CLI — retry shortly or contact support.

### Removed
