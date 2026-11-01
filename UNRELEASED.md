# Unreleased

### Added

- With the reporails plugin installed, a Claude Code session's start and end, prompts, file reads and edits, stops and compactions are recorded locally as event records (which file, which tool, when; never prompt or file text) in a private per-session file under `~/.reporails/xray/`, pruned by age and size. `ails events --session <id> -f json` prints a session's records in the order they were recorded, and `--after <next>` continues from the `next` offset the previous call printed, reading only what was recorded since. Recording never prints into or blocks the session, and nothing is sent anywhere.
- `ails xray` opens a local page that draws a Claude Code session's context window as a chart across the top, with the files the session could load in a list on the left and, on the right, a load order of what each turn held, which instruction files loaded and when, and each subagent's own context, or the text of the file you select, with buttons that check or fix one instruction file of the project the page lists. Files show relative to the project, or under `~/`. The page is served on 127.0.0.1 only and reads the session from local files; only the check and fix buttons reach the reporails server, as `ails check` does.
- The `ails xray` page lists what Claude Code put into a session's context before you typed anything (system prompt, skills, agents, MCP server instructions, deferred tools, session context, session-start hook notes) as size estimates, draws one point per reply, and shows the text of a selected instruction file, memory file, skill, agent or subagent brief, read on request and never stored.
- Each turn on the `ails xray` page lists the prompts you typed in it (text read on request, never stored), the notes hooks added to the context and the Stop blocks that sent the agent back to work, and the session-start list adds up what Claude Code announced before its first compaction. Compactions are drawn from the session's own transcript.
- The `ails xray` file list covers what a session in the folder can load: instruction, rule and memory files, and the skills, agents, commands and hook configs of the project, your user folder, the skills synced from your claude.ai account (`anthropic-skills:<name>`, the signed-in account only) and every installed, enabled plugin (`<plugin>:<name>`), each with where it comes from, its size and the name Claude Code uses. A memory file that `MEMORY.md` does not link within the part Claude Code loads is marked, and a skill, command or agent that ran counts as loaded from its turn; a skill run in its own subagent stays out of the main context, and a skill stays across a compaction as Claude Code re-attaches it.

- The `ails xray` page names the model that replied and, once a reply passes 200k tokens, scales its chart to the session's 1M-token context window. It draws every compaction, each one shaded only until the next, and a file loaded before a compaction counts as in context only until it. It counts, for each kind of artifact, how many are on disk, listed to the model, loaded and used, and what each file costs across the main session and every subagent that loaded it.
- The `ails xray` page shows a session as its agents: the main agent and every subagent, nested ones included, each on its own timeline with the instruction files, rules, skills, memory, MCP servers and hook notes it loaded at the moment they entered its context, its file reads, edits and shell commands beside it, what it was handed and what it handed back. Opening a subagent shows the same view of its own work.
- The `ails xray` page checks the project's files once when it opens, so each file's findings, counted by severity with its errors marked, show without a click, and a file you check lists each finding's severity, rule title, category and docs link with the command that fixes the file.

### Changed

- `ails expected-loads` also lists the skills, agents, commands and hook configs a session in the folder can invoke, from the project, your user folder, the skills synced from your claude.ai account and every installed, enabled plugin, and says for each memory file whether `MEMORY.md` links it within the part Claude Code loads. A malformed `installed_plugins.json` ends the command with the error and exit 2.
- Antigravity rules are now also found in `.agent/rules/`, `~/.gemini/antigravity-cli/rules/` and plugin `rules/` folders, and plugin `mcp_config.json` files are checked as MCP config.
- The Codex, Copilot, Cursor and Antigravity agent pages now state what each agent's docs say: Codex custom agents cannot override sandbox, approval, provider or MCP settings, Copilot's `excludeAgent` takes `cloud-agent`, Cursor ignores a plain `.md` in `.cursor/rules`, and Antigravity keeps hooks in `hooks.json`, not `settings.json`.

### Fixed

- A `heal_exclude` entry that is a bare file name now matches only at the project root, as documented, and the findings listed as `excluded` name the files they sit in.
- The hook event-type check for Antigravity, Codex and Copilot now accepts each agent's current hook events — Antigravity's `SessionStart` and Codex's `PreModelRequest` / `PostModelRequest` among them — instead of reporting them as unrecognized.
- An `@import` that resolves outside the current project is left as a literal reference instead of pulling that file's content into the check.
- `--heal` on a single file no longer writes through a symlink whose real path points outside the project.
- Files from your home folder and from installed plugins are found by walking only below their own folder, skipping `node_modules` and the other left-out folders, and a plugin folder with `[` or `*` in its path is read as written.
- A stored API key is sent only to the default server or a local (loopback) address, never to any other `AILS_SERVER_URL` the cli is pointed at.

### Removed

### Internal

- The `ails xray` view lists a session's agents as a tree (each with what its parent handed down, what it handed back, how it ended and the sources withheld from it), its sources with the agents that had each, and per agent the loads, MCP clusters, compactions, calls, repeated failing commands and idle breaks; the funnel and facts speak in source kinds.
- The `ails xray` transcript reader records each tool call (its category, MCP server, target path and a shell command's hash), each tool result's size and error state, and each subagent's description, parent, depth and brief size; `GET /call?id=` shows a shell call's command.
- The `ails xray` page draws a session as its agents on a timeline: subagent cards with launch and return arches, instruction files, rules, skills, memory, MCP and hooks where they entered each context, a side track of reads, edits and commands, and a findings drill-down per file; labels, agent types and source kinds come from the coding agent's own vocabulary, and the page ships Inter and JetBrains Mono.
- File names, prompts and file text on the `ails xray` page always show as plain text; markup in them never runs.

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
