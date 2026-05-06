# Unreleased

### Added

### Changed

- [framework/rules/claude]: Renamed `memory-file-within-200-lines` to `memory-file-within-size-limit` (`CLAUDE:S:0011`) — slug no longer embeds the line number, since the threshold is fundamentally agent-defined. Stays in the CLAUDE namespace: Claude is the only agent with a dedicated `MEMORY.md` file the rule's `match: {type: memory}` can check (Gemini's memory is a section in `GEMINI.md`; Copilot's is system-managed with a 28-day TTL; Codex has none; Cursor's mechanic is undocumented). Promotion to CORE was reverted — it was forward-looking but in practice would have only fired on Claude.

### Fixed

### Removed
