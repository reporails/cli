# Unreleased

### Added

- The x-ray page shows a placeholder of its layout while the session loads, instead of empty boxes and every tab stacked at once; a page that cannot load shows its notice in place of the placeholder, and with reduced motion set the placeholder does not shimmer.
- In the x-ray page, a hook that exited with an error without blocking counts as a firing and is listed as failed, with its exit code and error output.
- When the free hourly file budget is used up, `ails check` says so, with the budget, the files sent and when it resets, instead of an unknown error.

### Changed

- After `/clear`, `ails xray --current` and the agent's `xray` tool open the session the `/clear` started, not the one before it; when more than one session could be it, the page says it cannot tell which.
- Healing one file writes only that file; the files it imports are left as they are.
- For a session started in a subfolder of a git repository, the x-ray and `ails expected-loads` read the repository root's `.claude/settings.local.json`, as Claude Code does, so a hook declared there names its file.
- The x-ray page answers its first view sooner: the project check starts once the first view is shown.
- An x-ray page started in your home folder skips the whole-folder check and says why.

### Fixed

- `ails xray --background` and the agent's `xray` tool start the page from a `pip install --user` install.
- `ails hook` prints nothing, also when a settings file it reads is malformed, and records an event faster again.
- Skills synced from another claude.ai account are left out of the x-ray and `ails expected-loads`.
- `ails check` on a folder inside a git repository no longer warns `CORE:G:0001 Not a git repository`.

### Removed

### Internal
