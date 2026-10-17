# Unreleased

### Added

- The reporails plugin's context x-ray can now see which instruction files Claude Code should load in a project and why an AGENTS.md is skipped; an AGENTS.md that links to a CLAUDE.md is reported as that file rather than as skipped.

### Changed

### Fixed

- `ails check` reads a rule in your user rules folder (Claude Code's `~/.claude/rules/`, Antigravity's `~/.gemini/config/rules/`) as loaded at session start, as the agent loads it.

### Removed

### Internal
