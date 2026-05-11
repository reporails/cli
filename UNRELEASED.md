# Unreleased

### Added

- Tooling: `uv run poe specs_check` validates internal subsystem coverage (declared subsystems exist, each spec is within line-budget, modules colocate under one subpackage); `uv run poe spec_drift` flags potentially stale design docs whose source has been edited more recently
- Tooling: expanded `pytest` marker taxonomy in `pyproject.toml` for granular test selection (lane, cost, subsystem) with new poe tasks `test_fast`, `test_arch`, `test_contracts`, `test_markers`

### Changed

- Funnel: Rate-limit CTA now surfaces a "Try again in ~N min." hint when the server returns an accurate `reset_in`, between the limit blurb and the upgrade prompt
- Display: file rows now annotate duplicates with `(+alias)` labels — symlinked surfaces show the differing path component (e.g. `mintlify (+.claude)`), same-directory content-identical pairs show the alternate filename (e.g. `AGENTS.md (+CLAUDE.md)`)

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception
- Discovery: skill and rule files that appear under multiple agent surfaces via symlinks (e.g. `.claude/skills/` → `.agents/skills/`) are now collapsed to one canonical entry, eliminating duplicate findings and inflated scoring

### Removed
