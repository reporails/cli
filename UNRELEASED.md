# Unreleased

### Added

- The reporails plugin's context x-ray can now see which instruction files Claude Code should load in a project and why an AGENTS.md is skipped; an AGENTS.md that links to a CLAUDE.md, or is a copy with exactly the same text, is reported as that file rather than as skipped; your own `~/.claude/CLAUDE.md` and `~/.claude/rules/` files are listed, and under `managed-only` it leaves out exactly the files Claude Code leaves out at launch; an empty file, or one holding only frontmatter, which Claude Code sends nothing for, is not expected to load.

### Changed

- A global npm install stays on its version until you update it; `ails version` shows `npm` for an install from the npm package (npx included) and `ails update` prints the command that updates it.
- A run through the npm package no longer re-checks the package index for a newer release every time it starts.
- The context x-ray's event logs in `~/.reporails/xray/` are private to you, removed after 30 days (sooner if Claude Code is set to keep sessions for less), and the folder stays under 100 MB.
- `ails expected-loads` names, for each AGENTS.md Claude Code skips, the `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` that made it skip the file.
- The MCP `validate` tool now tells the agent which messages are announcements from reporails, so it shows them as announcements rather than as account messages.

### Fixed

- `ails install` run through npx, `pnpm dlx` or `bunx`, or from a project's own dependency, puts `ails` on your PATH instead of reporting that copy as already installed.
- A pinned `npx @reporails/cli@X.Y.Z` or `npm install -g @reporails/cli@X.Y.Z` runs that version; a bare `npx @reporails/cli` runs the latest release unless a copy is installed globally or in the project.
- `ails check` honours Claude Code's Project instructions setting saved under the plugin ID Claude Code has used since 2.1.285 (`cc-plugin-agents-md@builtin`), as well as the older `agents-md@builtin`.
- A rules file in a subdirectory's `.claude/rules/` folder is checked as loading on demand, as Claude Code loads it, rather than at session start.

### Removed

### Internal

- A build check fails when a fixed set of named values is spelled out as plain text in another list or table instead of using the names; the one place that did it, the capability-level table, now uses the names.
