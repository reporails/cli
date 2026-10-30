# Unreleased

### Added

### Changed

- Antigravity rules are now also found in `.agent/rules/`, `~/.gemini/antigravity-cli/rules/` and plugin `rules/` folders, and plugin `mcp_config.json` files are checked as MCP config.
- The Codex, Copilot, Cursor and Antigravity agent pages now state what each agent's docs say: Codex custom agents cannot override sandbox, approval, provider or MCP settings, Copilot's `excludeAgent` takes `cloud-agent`, Cursor ignores a plain `.md` in `.cursor/rules`, and Antigravity keeps hooks in `hooks.json`, not `settings.json`.

### Fixed

- A `heal_exclude` entry that is a bare file name now matches only at the project root, as documented, and the findings listed as `excluded` name the files they sit in.
- The hook event-type check for Antigravity, Codex and Copilot now accepts each agent's current hook events — Antigravity's `SessionStart` and Codex's `PreModelRequest` / `PostModelRequest` among them — instead of reporting them as unrecognized.
- An `@import` that resolves outside the current project is left as a literal reference instead of pulling that file's content into the check.
- `--heal` on a single file no longer writes through a symlink whose real path points outside the project.
- A stored API key is sent only to the default server or a local (loopback) address, never to any other `AILS_SERVER_URL` the cli is pointed at.

### Removed

### Internal

- Release and CI builds install from the lock file with a fixed `uv` version, a fixed `hatchling` version and commit-pinned GitHub actions.
- Tests: a property suite runs the real `ails` and the MCP server over a fixture set in text, JSON, `github` and MCP, and checks on every run that a disabled rule appears in no output, the total equals m_probe + client + server, every format carries one finding set, and the exit code matches the findings; the mutation probe accepts an upper-tier killing command.
- Tests: the unit tests for the per-source finding counts are removed; the total-equals-sum property covers them.
- CI runs the behavioral scenarios on every pull request, not only in the release gate.
- Tests: a skipped api-backed scenario leaves no temp directory behind, and the mutation probe's `--timeout` applies to a pytest target too.
- Internal restructuring of the package boundaries; command output is unchanged.
- `AILS_STAGE_TIMING=1` also prints the time of heal and of each MCP tool call.
- The torch import blocker is removed; nothing the cli installs imports torch.
- Tests: architecture checks guard the package boundaries, and `poe hexagon` renders the package dependency view.
