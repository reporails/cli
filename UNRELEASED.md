# Unreleased

### Added

- The reporails plugin's context x-ray can now see which instruction files Claude Code should load in a project and why an AGENTS.md is skipped; an AGENTS.md that links to, or is a copy with exactly the same text of, a CLAUDE.md that loads wherever the AGENTS.md would, is reported as that file rather than as skipped; your own `~/.claude/CLAUDE.md` and `~/.claude/rules/` files are listed; a project CLAUDE.md that links to your own `~/.claude/CLAUDE.md` is listed as the project's own file; under `managed-only` the x-ray leaves out exactly the files Claude Code leaves out at launch; an empty file, or one holding only frontmatter, which Claude Code sends nothing for, is not expected to load.

### Changed

- A global npm install stays on its version until you update it; `ails version` shows `npm` for an install from the npm package (npx included) and `ails update` prints the command that updates it.
- A run through the npm package no longer re-checks the package index for a newer release every time it starts.
- The context x-ray's event logs in `~/.reporails/xray/` are private to you, removed after 30 days (sooner if Claude Code is set to keep sessions for less), and the folder stays under 100 MB.
- `ails expected-loads` names, for each AGENTS.md Claude Code skips, the `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` that made it skip the file.
- The MCP `validate` tool now tells the agent which messages are announcements from reporails, so it shows them as announcements rather than as account messages.
- A folder value in `--exclude-dirs` or `exclude_dirs` that holds `*`, `?`, a backslash or a `..` step stops the run with an error that names the flag or the config file it came from and points to `--exclude-files` / `exclude_files` for file patterns; such a value used to be listed as left out while leaving nothing out. `ails config set exclude_dirs` refuses it before writing, with an error that names the setting, and the MCP tools answer `config_unreadable`.

### Fixed

- A first run through `npx` on a machine without `uv` installs `uv` and finishes your command, instead of stopping to ask you to restart your shell. The install messages go to stderr, so the command's own output, such as `-f json`, stays clean.
- `ails install` run through npx, `pnpm dlx` or `bunx`, or from a project's own dependency, puts `ails` on your PATH instead of reporting that copy as already installed.
- On Windows, `ails install` no longer counts an `ails` in the current folder or in uv's cache as installed, and an empty PATHEXT no longer hides an installed `ails`.
- `ails update` reports a uv run that cannot start or times out, instead of crashing.
- A project's CLAUDE.md that a subfolder's CLAUDE.md links to is listed and checked as the project's main file, not as that subfolder's file.
- A pinned `npx @reporails/cli@X.Y.Z` or `npm install -g @reporails/cli@X.Y.Z` runs that version; a bare `npx @reporails/cli` runs the latest release unless a copy is installed globally or in the project.
- `ails check` honours Claude Code's Project instructions setting saved under the plugin ID Claude Code has used since 2.1.285 (`cc-plugin-agents-md@builtin`), as well as the older `agents-md@builtin`.
- A rules file in a subdirectory's `.claude/rules/` folder is checked as loading on demand, as Claude Code loads it, rather than at session start.
- A space before the address in `AILS_SERVER_URL` no longer stops `ails check` from reaching that server.
- `--exclude-dirs` and `exclude_dirs` read a value with a `/` as a folder path from the project root: `/docs`, `./docs`, `docs/.` and an absolute path inside the project leave out the root's `docs` folder, where `/docs` and an absolute path used to leave out nothing and `./docs` every `docs` folder. The `Excluded` line lists such a folder as `./docs`. Folder names holding `[` and `]`, such as `[slug]`, can be left out.
- A folder you leave out by path is skipped during the scan, as a folder name is, so a large left-out folder costs no scan time, and an agent whose files sit only inside a folder left out in `exclude_dirs` is not detected. The scan does not enter a left-out folder through a symlink, or on Windows a junction, that points inside it either.
- The skill entry-point check no longer reports a skill folder you left out.
- On a run that names a file and also checks a folder or a capability listing, the `Excluded` line keeps a folder or pattern the named file sits in.
- `ails check --agent <name>` no longer checks another agent's file that you named inside a left-out folder.
- A run with no findings no longer says the score covers the rest of the project, since it shows no score.
- With `generic_scanning: true`, a failure while reading the files your instruction files import or link is logged as a warning instead of silently checking none of them.
- The over-cap message never suggests leaving out a folder whose name `--exclude-dirs` would refuse, and on Pro its lines end with a full stop.

### Removed

### Internal

- A build check fails when a fixed set of named values is spelled out as plain text in another list or table instead of using the names; the one place that did it, the capability-level table, now uses the names.
- Build checks fail when the environment is read, or a program is started, outside the one place that owns it.
- Every build check, not only the quick local one, fails on a test that is marked as more than one kind of test or as none.
