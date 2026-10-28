# Unreleased

### Added

### Changed

### Fixed

- A `heal_exclude` entry that is a bare file name now matches only at the project root, as documented, and the findings listed as `excluded` name the files they sit in.
- The hook event-type check for Antigravity, Codex, Copilot and Cursor now accepts each agent's current hook events — Antigravity's `SessionStart` and Codex's `PreModelRequest` / `PostModelRequest` among them — instead of reporting them as unrecognized.
- An `@import` that resolves outside the current project is left as a literal reference instead of pulling that file's content into the check.
- `--heal` on a single file no longer writes through a symlink whose real path points outside the project.
- A stored API key is sent only to the default server or a local (loopback) address, never to any other `AILS_SERVER_URL` the cli is pointed at.

### Removed

### Internal

- Release and CI builds install from the lock file with a fixed `uv` version, a fixed `hatchling` version and commit-pinned GitHub actions.
- Tests: a property suite runs the real `ails` and the MCP server over a fixture set in text, JSON, `github` and MCP, and checks on every run that a disabled rule appears in no output, the total equals m_probe + client + server, every format carries one finding set, and the exit code matches the findings; the mutation probe accepts an upper-tier killing command.
