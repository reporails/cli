# Unreleased

### Fixed
- [CORE]: Eliminate charge inversions in classifier — compound instructions ("Use X. Do not Y") now marked AMBIGUOUS instead of wrongly charged
- [CORE]: Colon-label rescue for "Label: Use X" / "Label: Never Y" patterns previously neutralized
- [CORE]: Add "pass" to ambiguous verb set — prevents status labels from triggering imperative classification
- [CORE]: Late-constraint guard catches negation after sentence/clause boundaries in imperative-classified atoms

### Added
- [CLI]: `ails update` command — upgrades CLI to latest version via `uv tool upgrade`
- [CLI]: `ails install` now installs `ails` to PATH (via `uv tool install`) in addition to MCP config
- [CLI]: MCP config uses direct binary path when available (faster startup, works offline)

### Changed
- [CORE]: Global mapper daemon — single process at `~/.reporails/daemon/` serves all projects
- [CORE]: Map cache moved to `~/.reporails/cache/map-cache.json` with LRU eviction (cap 5000)
- [CORE]: Per-project caches moved to `~/.reporails/cache/projects/<hash>/`
- [CLI]: `ails daemon start/stop/status` no longer require a path argument (deprecated)
- [CORE]: Project `.ails/` directory is now config-only — no runtime artifacts
