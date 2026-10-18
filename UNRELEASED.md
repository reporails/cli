# Unreleased

### Added

- The reporails plugin's context x-ray can now see which instruction files Claude Code should load in a project and why an AGENTS.md is skipped; an AGENTS.md that links to a CLAUDE.md is reported as that file rather than as skipped; your own `~/.claude/CLAUDE.md` and `~/.claude/rules/` files are listed, and under `managed-only` it leaves out exactly the files Claude Code leaves out at launch; an empty file, or one holding only frontmatter, which Claude Code sends nothing for, is not expected to load.

### Changed

- The MCP `validate` tool now tells the agent which messages are announcements from reporails, so it shows them as announcements rather than as account messages.

### Fixed

- `ails check` honours Claude Code's Project instructions setting saved under the plugin ID Claude Code has used since 2.1.285 (`cc-plugin-agents-md@builtin`), as well as the older `agents-md@builtin`.
- A rules file in a subdirectory's `.claude/rules/` folder is checked as loading on demand, as Claude Code loads it, rather than at session start.

### Removed

### Internal
