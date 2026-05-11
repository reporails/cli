# Unreleased

### Added

### Changed

- Funnel: Rate-limit CTA now surfaces a "Try again in ~N min." hint when the server returns an accurate `reset_in`, between the limit blurb and the upgrade prompt
- Display: file rows now annotate duplicates with `(+alias)` labels — symlinked surfaces show the differing path component (e.g. `mintlify (+.claude)`), same-directory content-identical pairs show the alternate filename (e.g. `AGENTS.md (+CLAUDE.md)`)

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception
- Discovery: skill and rule files that appear under multiple agent surfaces via symlinks (e.g. `.claude/skills/` → `.agents/skills/`) are now collapsed to one canonical entry, eliminating duplicate findings and inflated scoring

### Removed
