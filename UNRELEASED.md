# Unreleased

### Added

- With the reporails plugin installed, a Claude Code session's start and end, prompts, file reads and edits, stops and compactions are recorded locally as event records (which file, which tool, when; never prompt or file text) in a private per-session file under `~/.reporails/xray/`, pruned by age and size. `ails events --session <id> -f json` prints a session's records in the order they were recorded, and `--after <next>` continues from the `next` offset the previous call printed, reading only what was recorded since. Recording never prints into or blocks the session, and nothing is sent anywhere.
- `ails xray` opens a local page that shows a Claude Code session as its agents: the main agent and every subagent, nested ones included, each on its own timeline. Opening a subagent shows the same view of its own work, with the path back up and its parent's other subagents above it. Files show relative to the project, or under `~/`. The page is served on 127.0.0.1 only and reads the session from local files; only the check and fix buttons reach the reporails server, as `ails check` does.
- Each agent's timeline shows the instruction files, rules, skills, memory, MCP servers and hook notes it loaded at the moment they entered its context, its file reads, edits and shell commands beside it, a shell command that failed the same way three times or more as one bracket, and its compactions and long idle stretches. Each subagent shows what it was handed (its task, what it started with, and what its parent held that it did not get), how much work it did, and what it handed back, or that it was stopped, failed, is still running or never handed anything back.
- The Sources panel lists what a session in the folder can load: instruction, rule and memory files, skills and commands, MCP servers and hook notes, from the project, your user folder, the skills synced from your claude.ai account (`anthropic-skills:<name>`, the signed-in account only) and every installed, enabled plugin (`<plugin>:<name>`), each with its size, whether it loaded, was only listed or never loaded, and which agents had it. Focusing a source lights the agents that had it; a memory file that `MEMORY.md` does not link is marked, and layer toggles hide a kind everywhere at once.
- Prompts, subagent tasks, failing commands and file text are read on request and never stored, and names and text always show as plain text. The page names the model and its context window, checks the project's files once when it opens so each file's findings show without a click, and opens a file's findings, each with its severity, rule title, category and docs link, and the command that fixes the file.

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


- The `ails xray` page bundles the Inter and JetBrains Mono fonts (SIL Open Font License), so it loads no web fonts.
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
