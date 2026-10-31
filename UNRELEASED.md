# Unreleased

### Added

- With the reporails plugin installed, a Claude Code session's start and end, prompts, file reads and edits, stops and compactions are recorded locally as event records (which file, which tool, when; never prompt or file text) in a private per-session file under `~/.reporails/xray/`, pruned by age and size. `ails events --session <id> -f json` prints a session's records in the order they were recorded, and `--after <next>` continues from the `next` offset the previous call printed, reading only what was recorded since. Recording never prints into or blocks the session, and nothing is sent anywhere.
- `ails xray` opens a local page that draws a Claude Code session's context window as a chart across the top, with the files the session could load in a list on the left and, on the right, a load order of what each turn held, which instruction files loaded and when, and each subagent's own context, or the text of the file you select, with buttons that check or fix one instruction file of the project the page lists. Files show relative to the project, or under `~/`. The page is served on 127.0.0.1 only and reads the session from local files; only the check and fix buttons reach the reporails server, as `ails check` does.
- The `ails xray` page lists what Claude Code put into a session's context before you typed anything (system prompt, skills, agents, MCP server instructions, deferred tools, session context, session-start hook notes) as size estimates, draws one point per reply, and shows the text of a selected instruction file, memory file, skill, agent or subagent brief, read on request and never stored.
- Each turn on the `ails xray` page lists the prompts you typed in it (text read on request, never stored), the notes hooks added and the Stop blocks that sent the agent back to work, and the session-start list adds up what Claude Code announced before its first compaction.

### Changed

- The `ails xray` file list now also shows the skills, agents, commands and hook configs from your user folder and from every installed, enabled plugin, plus rule files, each with where it comes from and a short name, and marks a memory file that `MEMORY.md` does not link within the part Claude Code loads.
- The `ails xray` page draws a compaction from the session's own transcript, so a session without recorded events still shows when it compacted and whether it was manual or automatic, and a skill's supporting files no longer appear as instruction files of their own.
- Antigravity rules are now also found in `.agent/rules/`, `~/.gemini/antigravity-cli/rules/` and plugin `rules/` folders, and plugin `mcp_config.json` files are checked as MCP config.
- The Codex, Copilot, Cursor and Antigravity agent pages now state what each agent's docs say: Codex custom agents cannot override sandbox, approval, provider or MCP settings, Copilot's `excludeAgent` takes `cloud-agent`, Cursor ignores a plain `.md` in `.cursor/rules`, and Antigravity keeps hooks in `hooks.json`, not `settings.json`.

### Fixed

- A `heal_exclude` entry that is a bare file name now matches only at the project root, as documented, and the findings listed as `excluded` name the files they sit in.
- The hook event-type check for Antigravity, Codex and Copilot now accepts each agent's current hook events — Antigravity's `SessionStart` and Codex's `PreModelRequest` / `PostModelRequest` among them — instead of reporting them as unrecognized.
- An `@import` that resolves outside the current project is left as a literal reference instead of pulling that file's content into the check.
- `--heal` on a single file no longer writes through a symlink whose real path points outside the project.
- The `ails xray` file list shows each file's size again, lists a plugin skill as `<plugin>:<skill>` as Claude Code names it, and counts a hook's output as context only for the events whose output Claude Code adds to the context (`UserPromptSubmit`, `UserPromptExpansion`, `SessionStart`, `PostModelSwitch`).
- On the `ails xray` page, a tool or agent Claude Code retracts takes its size off the session-start list with it, and a listing the harness sends after the last turn no longer draws an empty turn.
- A malformed `installed_plugins.json` no longer ends `ails expected-loads` in a traceback or makes the `ails xray` page fail: the command prints the error and exits 2, and the page lists no plugin files and shows the error as a banner.
- Files from your home folder and from installed plugins are found by walking only below their own folder, skipping `node_modules` and the other left-out folders, and a plugin folder with `[` or `*` in its path is read as written.
- A stored API key is sent only to the default server or a local (loopback) address, never to any other `AILS_SERVER_URL` the cli is pointed at.

### Removed

### Internal

- The `ails xray` page bundles the Geist and Geist Mono fonts (SIL Open Font License), so it loads no web fonts.
- Release and CI builds install from the lock file with a fixed `uv` version, a fixed `hatchling` version and commit-pinned GitHub actions.
- Tests: a property suite runs the real `ails` and the MCP server over a fixture set in text, JSON, `github` and MCP, and checks on every run that a disabled rule appears in no output, the total equals m_probe + client + server, every format carries one finding set, and the exit code matches the findings; the mutation probe accepts an upper-tier killing command.
- Tests: the unit tests for the per-source finding counts are removed; the total-equals-sum property covers them.
- CI runs the behavioral scenarios on every pull request, not only in the release gate.
- Tests: a skipped api-backed scenario leaves no temp directory behind, and the mutation probe's `--timeout` applies to a pytest target too.
- Internal restructuring of the package boundaries; command output is unchanged.
- `AILS_STAGE_TIMING=1` also prints the time of heal and of each MCP tool call.
- The torch import blocker is removed; nothing the cli installs imports torch.
- Tests: architecture checks guard the package boundaries, replacing two narrower checks they cover, and `poe hexagon` renders the package dependency view.
- Checking or fixing one file runs through one shared path for every interface; MCP replies are unchanged, and an architecture check stops one interface importing another; a test shows the page's fix button writing every fix and putting back a file that departs.
