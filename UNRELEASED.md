# Unreleased

### Added

### Changed

- Funnel: Rate-limit CTA now surfaces a "Try again in ~N min." hint when the server returns an accurate `reset_in`, between the limit blurb and the upgrade prompt

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception

### Removed
