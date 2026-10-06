# Changelog

## 0.6.1

### Breaking changes

- `ails auth login`, `ails auth logout`, `ails auth status` and `ails auth token` are replaced by `ails login` and `ails logout`. Upgrading from 0.6.0: run `ails update`, then `ails login`.
- CI and the GitHub Action use an API key created on reporails.com/account, set as `AILS_API_KEY` (or the Action's `api-key` input); `ails auth token` is gone.

### Added

- `ails login` signs this machine in to your account through your browser: it prints a link and a short code, opens the browser when it can (also when a coding agent runs it), and finishes when you approve. The link is valid for 30 seconds; when it runs out, run `ails login` again. One sign-in per machine, lasting a year, and your plan (Free or Pro) comes from your account, so a second machine or a CI key never affects the others. On a machine that is already signed in it shows who is signed in and on which plan, and signs in again when that sign-in has ended. Where no browser can open, as in most SSH sessions, it prints the link instead, and after too many attempts from one network it says how long to wait.
- `ails logout` signs only this machine out, and still removes the local sign-in when the website cannot be reached or the saved sign-in file is damaged.
- Messages about your account (a failed payment, Pro ending, an announcement) appear under the header of `ails check` (indented, and wrapped to the output width), as a `notices` list in `--format json` (also with `--heal`), as annotations in `--format github`, and in the MCP `validate` reply. A warning shows on every run; other messages once a day.

### Changed

- The docs cover the messages about your account (a failed payment, Pro ending) and add FAQ answers for signing back in, signing in over SSH, and CI after the move to API keys.
- `ails update` also says how to update the reporails plugin in Cursor, GitHub Copilot and Antigravity, which install it by hand.
- Sign-in hints, `ails --help`, the npm wrapper's help and the docs point to `ails login` and `ails logout`. For CI and the GitHub Action, create an API key on reporails.com/account and set it as `AILS_API_KEY`.
- Check: the first `ails check` on a large project, before anything is cached, finishes sooner.
- Check: every `ails check` in a large repository finds its files faster: the folders it skips (`.git`, `vendor`, `node_modules` and your `exclude_dirs`) are no longer searched.

### Fixed

- A check run in the first minutes after signing in, while the sign-in is still reaching the server, says to try again in a minute instead of saying the sign-in ended.
- Check: instruction files inside symlinked folders, such as a shared rules folder linked into `.claude/rules/` or a skill folder linked into `.claude/skills/`, are found and checked.

### Internal

- The MCP server asks again when a new sign-in is still reaching the server instead of remembering that reply, and heal does not read that reply as no account.
- The MCP server's idle model release has its own module.
- The API key, the upgrade link and the server's retry wait are each read in one place; the plugin's server starts this release or a newer one in its line.
- The stored sign-in is read through one reader, and messages from the server are read off a reply and remembered once shown.
- Every unit test added in this release carries its subsystem marker on the test itself.
- The faster first check keeps memory use flat on very large projects, sees files created between checks in a long-running MCP server, works with a relative project root, and reports a looping symlink once per walk; the new batching has model-free unit tests.

## 0.6.0

### Breaking changes

- The analysis model is no longer inside the package: the first `ails check` on a machine downloads it (about 275 MB) and needs network access once; later runs work offline. In CI or a locked-down network, allow that download first. If it cannot be reached, `ails check` stops with exit code 2.
- `ails check --format compact` and `--format brief` are gone, and an unknown format now exits with code 2 instead of falling back to the scorecard. Use `text`, `json` or `github`.
- The text summary now reads `Quality`, `Fix now` and `Findings`; the separate error/warning/info headline is gone. Read those counts from `stats` in `-f json` if a script parsed them.
- In `-f json`, `stats.cross_file_conflicts` is gone and the per-file `regime` block carries only `triage_tier`; `named`, `within_capacity` and `confidence` no longer appear. Update any script that reads them.
- A check that could not reach the diagnostic backend now puts a `server_error` object in `--format json` and `--format github`, and a CI `min-score` gate no longer passes on an outage. Expect failures where an outage used to read as a clean run.
- Text findings no longer carry an indented fix line. Fixes reach your coding agent through the reporails plugin (`ails install`, then `/reporails:ails heal` in Claude Code) and per finding in `-f json`.
- `ails check --heal` no longer writes placeholder sections into your files; it lists what each file needs so you write the content.
- In `.ails/config.yml` and `~/.reporails/config.yml`, the `overrides:` key and `framework_version` are removed, and `ails config set tier` is rejected as an unknown key. Move a per-rule `min_lines` threshold to the top-level `rule_thresholds:` key; a rule's severity comes from its rule file.
- Rule severities changed across the core ruleset, so low-severity findings display as `info` instead of `warning`. Check any CI step that matches on `warning`.
- `CORE:C:0044` changed meaning: it was the per-file "Capacity saturation across N topics" finding and now reports topic overlap between files that load together ("Topic Overlap Across Elements"). Review any suppression, threshold or CI match keyed on that rule id.

### Added

- Pro: `ails auth login` and the `ails check` footer now say where rewriting runs: `ails install` adds the reporails plugin, then `/reporails:ails heal` in Claude Code (in other agents, ask your agent to run the reporails heal). `ails check --heal` is described as applying formatting fixes. The README, tiers, getting-started and FAQ pages say the same.
- Install: `ails install` now installs the reporails plugin into Claude Code and Codex when they are on this machine, gets its first start ready, and ends with the sign-in step; Cursor, GitHub Copilot and Antigravity get their install steps printed, as do Claude Code and Codex when their command is not on this machine or a step fails. It installs for your user also when the repository you are in already has the plugin for the project. A `reporails` marketplace that points at another source, a local folder included, is replaced, and the last line names heal as a Pro command unless your account is on Pro. `npx @reporails/cli install` puts `ails` on your PATH also when uv keeps its cache somewhere other than the default.
- Install: `ails install --project` installs the plugin for the repository you are in (its root, also from a subfolder; the inner repository when one sits inside another) only, shared with collaborators through its Claude Code settings; a collaborator who runs it gets the plugin from those settings. Codex installs for your user.
- Update: `ails update` also refreshes the reporails plugin in each agent that has it, in each scope it is installed in, says when it replaces a marketplace's old source, and points to `ails install` for an agent without it.
- Check: a skill, rule or agent whose frontmatter is not valid YAML is reported as a finding on `CORE:S:0040`, `CORE:S:0006` or `CORE:S:0057`, with the problem and its line.
- Check: a skill's supporting markdown files (`reference.md`, `examples/*.md`) are discovered, checked with the skill and seen by the MCP change check; the skill-only frontmatter and length rules do not report on them. A skill's whole folder is one skill in the report: its supporting files are listed under Skills, named by their path inside the skill (`ails/workflows/heal.md`), and count toward the Skills score in the terminal, `--format json` and MCP `validate`. The terminal counts each skill once, and `ails check skills` gives one score per skill. A `SKILL.md` inside a skill's folder is one of that skill's files, so the skill-only rules check only the skill's own `SKILL.md`. A skill counts where its agent loads it: Claude Code, Codex, GitHub Copilot and Antigravity load a `SKILL.md` that sits directly in a folder under `skills/`, and Cursor also loads one inside a category folder. A `SKILL.md` its agent does not load is checked as a plain file, without the skill rules, and named by its path. A skill file checked on its own (`ails check .claude/skills/foo/reference.md`) is still checked as part of its skill. In the paid workflow each skill is one location with all its files, and each skill in a Cursor category folder is a location of its own.
- Rules: a check in `checks.yml` can declare `project_scope: once` to report a project-wide fact once per project, also on a run that names a file or folder (`project_scope: aggregate`, formerly `true`, keeps a check off a narrowed run), and `convention: true` to mark a missing-documentation finding.
- Paid remedy: a paid `validate` / `check` returns a `workflow` — the parts of your project that need a rewrite, as locations (the main file, each skill, each agent, each rule file, …) — in `--json` output and in the MCP `validate` tool. A location's `kind` is the file type your agent's config gives it (`main`, `rules`, `memory`, `skills`, `agents`, `commands`, `hooks`, …). Kinds that load at session start come first, then the kinds your agent invokes, then the kinds loaded on demand; within a kind the most important rewrite comes first. A skill or agent is recognized by its type wherever it lives, and a skill's supporting files belong to the skill's own location. The free and anonymous tiers do not receive it; clients that do not know the new key ignore it. Your coding agent works through the locations one at a time, and each finished location re-ranks the next against the improved files, so a large project's remedy no longer arrives as one wall of fixes.
  - Every firing rule is accounted for: a contract defect (a broken link or import, a malformed hook, a skill or subagent missing its required frontmatter, a committed secret) or a finding that lowers how much of a file reaches the model is part of its location's rewrite, ahead of other fixes; every other firing rule is listed under `workflow.listed` with the reason it needs no rewrite and how many findings it covers.
  - A finding you silence with `<!-- ails-disable-line <rule> -->` no longer lowers its file's score. It is also left out of the paid rewrite workflow and the briefs built from it. Several directives inside a file brought in with `@path` each silence the instruction on their own line there, instead of the last one deciding for everything that import brings in.
  - A relation between two files (a repeated instruction or an overlapping topic) attaches to exactly one location — the file that should change — and names the file that keeps the content as its partner.

- Paid remedy: the new `remedy_brief(path, location)` MCP tool returns everything your coding agent needs to rewrite one location whole: the project root and each file's absolute path (so a project other than your agent's working directory is rewritten in place), each file's current score, every instruction (with its direction, the names it carries and the rules that flag it) and heading, the location's findings, weakest first, and cross-file relations with their remedy text, a guide to what an ideal instruction looks like (a passing and a failing example per trait), the rules that govern this kind of file, and the preservation contract the rewrite must keep. The brief also carries a `procedure`: the line fixes to apply first (backticks around a bare code name, italics for a bolded prohibition) for the location's own files only, none on a line you silenced with `ails-disable-line`, then the kind's rules in the order to work them. A large brief arrives in numbered parts that each fit the client's output limit. `validate` itself returns only the location index — order, label, kind, loading, files and importance — so a large project's reply stays small.

- Paid remedy: after your coding agent rewrites a briefed location, `validate` on each rewritten file reports a `preservation` check — whether the rewrite kept every instruction with its polarity, every stated fact, named construct, table row, list item, heading, fenced example, link and the constraint beside its directive, plus the file's score before and after. It also reports `added_instructions` (an instruction the original gave no basis for, such as a new prohibition, which makes `preservation.ok` false), a tool, file or command name the rewrite introduced that does not exist in the project, and a name the file already uses that the rewrite repeats more often than its instructions account for. Dropping only an example or a reason from a prohibition is not reported as a change to what it forbids. The file's remaining findings are listed weakest first with their remedies, so the agent revises exactly what is still weak. A list item moved into another list or section is reported as moved; a list moved whole is not. A packed sentence split into several instructions, an instruction reworded in place, a heading added over an unheaded block and a reflowed list are not reported. Only a duplicate a relation's remedy names, or a line a finding's own remedy says to trim, may be deleted. Each finding the remedy leaves as is carries one plain sentence on what leaving it means and what you can do. An instruction on a line that a trim finding points at is still reported when a rewrite drops or reverses it; only the surrounding context on that line may go.

- Paid remedy: `validate` and `remedy_brief` take a `targets` argument — the same tokens `ails check` reads (`skills`, `skills:<name>`, `agents:<name>`, `@main`, or a path). The project is still diagnosed whole, but `validate` returns only the locations, findings, cross-file entries and pair counts of the named files, renumbered from 1, while `stats`, `surface_health`, `level`, `pro` and `workflow.listed` stay whole-project. Pass the same `targets` to `remedy_brief`.

- MCP `validate`: every reply carries a `rules` map giving each rule it names its title and a link to its documentation page, so your coding agent can show a rule by title instead of a bare code.

- Rules: five new rules for the subagent, plugin and skill surfaces, each applying only to agents that have that surface.
  - **`subagent-frontmatter-identity`** (`CORE:S:0057`): a `.claude/agents/*.md` file declares both `name` and `description`.
  - **`subagent-tools-field-canonical`** (`CORE:C:0056`): a subagent restricts tools with `tools` / `disallowedTools`, not the skill field `allowed-tools`, which subagents ignore.
  - **`subagent-system-prompt-no-secrets`** (`CORE:G:0009`): no credential, API key or private key in a subagent definition. A secret there is reported once, by this rule, at `error` severity; silencing this rule on that line with `ails-disable-line` still reports it as a credential.
  - **`plugin-manifest-required-keys`** (`CORE:S:0058`): a `.claude-plugin/plugin.json` declares `name` and `description`.
  - **`skill-invocation-reachable`** (`CORE:C:0057`): a `SKILL.md` does not set both `disable-model-invocation: true` and `user-invocable: false`, which leaves the skill usable by neither the model nor the user.

- Rule authors: a rule can target subagent definitions and plugin manifests (`match.type: agents` / `plugins`). A rule can declare `requires_capability: <name>` (a capability from `framework/capabilities_matrix.yml`, such as `memory`, `hooks`, `skills`) and then applies only when the selected `--agent` has it; agent-agnostic scans and agents not in the matrix are not filtered. `enforcement_required` and `enforcement_mechanism` (`hook`, `permission`, `ci`, `managed_settings`, `static_analysis`) mark a concern that needs an enforcement partner outside the instruction file, and `surface_mutations` gives per-surface overrides. The hook, permission, CI and managed-settings governance rules now set the enforcement fields. `ails test --lint` flags a rule that sets `enforcement_required: true` without an `enforcement_mechanism`. No finding or score changes.

- Licence: the analysis model files are licensed under the Reporails Model Licence (`LICENSE-weights`). You may run them through `ails` on your own instruction files and use the results; you may not use the model files or their results to train, fine-tune or distil any machine-learning model, offer them as a competing product or service, run them outside the CLI, redistribute them, or reverse-engineer them. The bundled third-party embedding model keeps its Apache-2.0 licence (see `NOTICE`). The licence ships with the package and is downloaded next to the model files. No change to `ails` behaviour or output.

- GitHub Action: the model downloads on the first run only; later runs on the same runner OS restore it from the Actions cache, including after a failed check (for example `strict` findings). On a pull request, unchanged instruction files are served from the previous run's analysis, so only the files the change touches pay the cold cost; the score matches a full cold run, and a fresh clone with no prior cache does a full analysis. A workflow that runs `ails` directly can cache the model the same way ([Configuration → Caching the model in CI](docs/configuration.md#caching-the-model-in-ci)); when `ails` downloads the model inside GitHub Actions it prints a line pointing there.

- Check (free / anonymous): `ails check` returns the full diagnosis for every finding, without the paid remedies; the local fix suggestions are unchanged, and the remedies and the order to apply them are a paid feature.

- Check: a sentence that gives more than one instruction — commands joined by a comma, a semicolon, a dash, "and" or "then" — is read as one instruction each, and scores like the same instructions written as separate sentences. **One Instruction Per Sentence** (`CORE:C:0058`) reports such a sentence and names its instructions, because instructions sharing a sentence compete and some are not followed. It runs with every check, offline included. A condition written before a command ("…; when the build fails, run it again") is read with that command, the last item of an "and" list ("Preserve `id`, `slug`, and coordinate fields") stays part of the list, and a "See" pointer's title ("See the build and deploy guide.") is one pointer. Scores change on files that hold such sentences.

- Check: three rules that were documented but never reported now fire. **Instruction Ordering** (`CORE:D:0003`) reports a prohibition that comes before every directive on its topic and a paid plan offers a fix for it. **Specificity Shields Against Competition** (`CORE:C:0050`) reports a vague instruction whose same-topic context is large enough to weaken it; beyond that the finding stays Content Dilution (`CORE:C:0041`). **Default Behavior Competition** (`CORE:C:0052`) reports a vague, hedged instruction with no stronger instruction on its topic. The repeated-instruction finding now names its rule, **No Cross-File Duplication** (`CORE:C:0040`).

- Check: a Claude Code check includes your `AGENTS.md` exactly when Claude Code reads it — when no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` sits in the project or a folder above it, or when your Claude Code settings (`instructionFiles: claude-md-and-agents-md` under the built-in `agents-md` plugin) ask for both; with `claude-md` or `managed-only`, or with that plugin turned off, it stays out. A subfolder's `AGENTS.md` is checked as loading when work reaches that subfolder, unless the subfolder has its own `CLAUDE.md`. An `AGENTS.md` that Codex, Cursor or Copilot reads as its own main file stays with that agent, and a project whose only Copilot file is a root `AGENTS.md` that another detected agent also reads is no longer reported as a Copilot project. A Claude Code plugin's own skills, agents, commands and output styles — at the repository root or in a marketplace's `plugins/<name>/`, marked by `.claude-plugin/plugin.json` — are found and checked as Claude files; a folder you cannot read is skipped.

- Check: set `segmentation: structure-aware` in `.ails/config.yml` to analyze each whole sentence, or each whole list or numbered item, as one unit instead of splitting prose at inline commas, colons or dashes. The default (`legacy`) is unchanged, so behaviour only shifts when you opt in. A line that is wholly a quotation stays one unit in this mode too.

### Changed

- Check: each agent's files are found where that agent's own documentation says it loads them.
  - Claude Code: commands in subfolders of `.claude/commands/` (`/frontend:component`); rules, skills, subagents and output styles in `.claude/` folders below the project root; `CLAUDE.local.md` in subfolders; managed skills, subagents and output styles in `.claude/` inside the managed settings folder, Windows included; a plugin's `hooks/hooks.json` and `.mcp.json`.
  - Cursor: skills in `.cursor/skills/` and `.agents/skills/` below the project root, and `BUGBOT.md` in subfolders. A plain `.md` file in `.cursor/rules/` is no longer checked as a rule, since Cursor ignores it.
  - Codex: skills in `.agents/skills/` in any project folder; skill metadata (`agents/openai.yaml`) only inside a skill folder; the managed `/etc/codex/managed_config.toml`.
  - GitHub Copilot: `.md` subagents in `.github/agents/`; user skills and subagents in `~/.claude/`; `~/.copilot/copilot-instructions.md` and `~/.copilot/instructions/`; hook files in `~/.copilot/hooks/` and `/etc/github-copilot/policy.d/`, and the Copilot settings files that carry hooks (`.github/copilot/settings.json`, `.github/copilot/settings.local.json`, `~/.copilot/settings.json`), whose hooks count toward the Level line and `ails check hooks`.
  - Antigravity: rules in `.agents/rules/` in any folder and in `~/.gemini/config/rules/`, whose file names Descriptive Filenames (`CORE:S:0014`) now checks; its global instruction files, skills, subagents, plugins, settings, keybindings and hooks in `~/.gemini/config/` and `~/.gemini/antigravity-cli/`.
- Check: the Level line shows the richest capability a project uses — skills (Delegated), sub-agents (Abstracted), hooks (Governed) or memory (Adaptive) set it on their own, with no path-scoped rules needed below them; an MCP config on its own no longer reads as Governed; a plain git hooks folder adds no level, and one agent's hooks or memory never raise the level of a check run for another agent.
- Heal: the bold-to-italic fix changes exactly the bold the bold check reports on an instruction: a title label and a negation phrase such as "don't" are left as they are, `not` and `No` are changed, and `__bold__` is changed too.
- Heal: a line holding escaped backticks inside inline code (`` `Use \`ruff\`` ``) no longer fails the rewrite check when the rewrite keeps it, so heal no longer restores the file because of that line.
- Check: a bold label that opens a line (`**Rule:** …`, `**Term** — …`, `__Rule__: …`) is read from the markdown parse, and a heading or sentence that opens with a number ("2026 roadmap") keeps its number when its wording is classified.
- Check: a file's frontmatter block is found the same way everywhere: it opens and closes on a whole `---` line, so a `----` line or a `---` inside a value no longer ends it, and a problem is reported at its own line in the file.
- Check: bold and italic in an instruction are read the way markdown reads them: `_x_` is italic, `__x__` is bold, an escaped or unmatched star and a star inside a code span are not emphasis, and an italic run inside a bold one counts as bold. The first run after the upgrade rebuilds the local analysis cache once.
- Rules: the `content_format` a rule can match on, and the `valid_markdown` mechanical check, read a file's markdown structure from the parse: examples inside nested or indented blocks, links shown in code and HTML comments no longer count as formats, and a `#!/bin/bash` or `# comment` line inside a code block is not a broken heading.
- Check: a file-type pattern and a machine-config surface match paths with the same glob rules as the rest of file classification, so `*` in a pattern such as `.claude/rules/*.md` stays within one folder.
- Check: an agent is named only from a clue that points at it (its own folder, a root file name no other agent uses, or a Codex fallback-filenames setting in the project's config); a folder with only `AGENTS.md` or editor settings is checked with the rules every agent shares, and the summary says the agent was not determined and how to name it (`--agent`, `default_agent`). Skills under `.claude/skills/` name Claude; a bare `skills/` folder does not.
- Check: agent and skill files in nested folders (`.claude/agents/team/lead.md`) are claimed by their file type, so the rules for that type apply to them.
- Config: `**` in `exclude_files` matches zero or more folders.
- Rewrite check: it reads tables, lists, headings, fenced blocks and links from the document structure, so a link shown inside code is not counted, a list inside a quote and a table without leading pipes are seen, and a hedge made "must" or "shall" is listed as made direct (only a new "Never" or "Always" fails).
- Check: `ails check` finds a large project's instruction files in a fraction of the time it took, a skill's or agent's description is encoded once and remembered between runs, and every file search skips the same excluded folders (the built-in list plus your `exclude_dirs`).
- Score: a line ending with a colon that introduces a list, code block or table is no longer scored as a too-brief instruction and is never offered for trimming; this holds above a list of very short items too, and a colon in the middle of a paragraph or above lines that only look like a list does not count.
- Score: an instruction carrying both italics and backticks is scored for its backticks, so italicising a named construct no longer lowers a score.
- Check: an instruction is reported as vague only when its section names a code construct it could name; an instruction about prose or behaviour is left alone.
- Check: a library or tool name written in prose (`Django`, `WebSocket`, `pytest`) is reported as unformatted code, and wrapped by `--heal`, only when the same file writes it in backticks elsewhere.
- Rewrite check: an instruction opening with "Prefer", "Consider", "Try", "Perhaps", "Maybe", "Possibly" or "Ideally" is treated as a hedge, so making it direct is listed and making it "Never" or "Always" fails.
- Check: "Not a git repository" is reported once per project instead of once per agent's main file, also when the project is given by path.
- Check: the missing-documentation convention warnings show as one counted line per file (for example "19 documentation conventions not present"), with `-v` to list them; they are left out of the text output's findings total and top rules. JSON and MCP results keep every finding and mark these with `"convention": true`.
- MCP: `validate` on a large project answers a repeat call in about a second instead of ten or more, and a call after an edit in about half the time.
- Rewrite check: a rewrite that turns a hedge into an order ("prefer X" to "use X", "Consider running X" to "Run X", "Consider avoiding X" to "Avoid X") passes and is listed with the line before and after; the heal report shows each one as made direct.
- Rewrite check: a directive the rewrite appends is reported as an added instruction, as an appended prohibition already was.
- Licence: a third-party notice (`NOTICE`) and the Apache License 2.0 text (`LICENSE-APACHE-2.0`) ship in the package and are downloaded next to the model files; the package metadata names the licensor (Mészáros Gábor e.v., trading as Reporails) and both licences.

- Rules: a finding is not repeated where the rule it builds on already reports.
  - A project with no prohibition reports Explicit Prohibitions (`CORE:C:0019`) once, without Safety Gate Directives (`CORE:C:0022`) and Forbidden Commands Defined (`CORE:G:0004`).
  - A project with no directive reports Directive Density (`CORE:D:0001`) without Critical Instructions at Edges (`CORE:C:0036`), Instruction Rationale Present (`CORE:C:0038`) and Subdirectory Instruction Files (`CORE:S:0037`).
  - A file with no headings reports Section Headers Present (`CORE:S:0002`) without Layered Content Structure (`CORE:S:0016`), Related Instructions Grouped (`CORE:E:0005`) and Single Topic Per Section (`CORE:S:0019`).
  - A path-scoped file whose import target is missing reports Import Targets Resolve (`CORE:S:0024`) without Import References Resolve (`CORE:S:0026`).
  - For an agent that does not use the rule a finding builds on, the finding reports on its own: a Copilot project reports Import References Resolve (`CORE:S:0026`) as before.
- Rules: ten rules report as warnings and do not lower a file's score: Explicit Prohibitions (`CORE:C:0019`), Safety Gate Directives (`CORE:C:0022`), Directive Density (`CORE:D:0001`), Critical Instructions at Edges (`CORE:C:0036`), Section Headers Present (`CORE:S:0002`), Exact Filename Convention (`CORE:S:0004`), Descriptive Filenames (`CORE:S:0014`), Expected Directories Exist (`CORE:S:0008`), Modular File Organization (`CORE:S:0010`) and Vcs Tracked (`CORE:G:0001`). A local finding lowers a score only when content fails to load: a missing root instruction file, invalid markdown, a broken import or link, an import chain that is too deep, a skill directory holding a README, or an agent's own size and path-scope limits. Scores rise on files that failed one of the ten.
- Findings: a finding the rewrite workflow lists shows the same impact tier in its file's finding list as in the workflow.
- Findings: a file-wide summary ("Too weak to be effective", "None of the instructions name specific constructs") is left out of a file's findings when the file already lists, line by line, the findings it sums up. The score is unchanged.

- Paid remedy: in the `workflow`, a sentence that packs several instructions is one finding that holds the findings on each of its instructions in `members`, and an instruction with several weaknesses is one finding that holds each weakness. Every workflow finding carries `members` (empty when it holds none), in `--format json`, the MCP `validate` reply and `remedy_brief`. Silencing a rule on that line with `ails-disable-line` removes only that finding from the group.
- Text output: the findings on the instructions of a line reported as packing several instructions are shown indented under that line's row, each once; when a line holds two such sentences they sit under the first. A finding on that line that is not about an instruction, such as a broken link, stays in the file's own list. The finding counts are unchanged.

- Rules: a Broad Conditional Scope finding is reported under its rule id `CORE:C:0060`. Silence it with `ails-disable-line CORE:C:0060` or `ails-disable-line broad-conditional-scope`; the `scope` token is not accepted. On a paid plan it is part of the rewrite workflow and comes with a remedy.

- GitHub Action: `uses: reporails/cli/action@<version>` runs that release of the CLI by default instead of the newest one on PyPI; set `version:` to run a different one.

- Check: a plain whole-project run also checks each agent's hook, permission, MCP and plugin config files, the same way `ails check hooks` does. `ails check <project>/.claude/settings.json` checks that file from any folder, including a project that is not a git repository. A file in your home-level agent folder (`~/.claude/CLAUDE.md`, `~/.claude/settings.json`) is checked on its own with the rules its type gets, without scanning the rest of the home directory, and a hidden folder that is not an agent's own no longer decides which project a file belongs to.

- Check: hook rules for Claude, Codex, Copilot and Cursor (event names, handler types, command and prompt fields, the project-directory variable, hard-coded paths) fire only on a config file that declares a hooks block, and the command-field and project-directory checks fire only where a command handler exists; a project-directory reference outside the hook commands no longer satisfies the project-directory check. Each handler is checked on its own line: a command handler without its command, a handler with a missing or unsupported type, and a prompt handler with a missing or empty prompt are reported even when another handler in the same file is valid. Only the handlers a hook config declares are judged: an unrelated object elsewhere in the file is no longer reported as a broken handler, and a command handler that holds other keys but no command is now caught. Cursor, Copilot and Antigravity hooks written in each tool's documented form — handlers without a `"type"`, commands relative to the project root — no longer draw missing-handler or project-directory findings. A settings file that holds only permissions, MCP servers or plugins scores clean instead of drawing hook findings; a broken hooks block is still caught, but a hook config that does not parse draws no handler finding. Hook rules apply only to agents that support hooks.

- Check: the position rule (`CORE:C:0047`) fires only on a prohibition that names what it forbids, sits early among instructions on unrelated subjects and has no directive on the same subject; an abstract or unnamed instruction early in a long file no longer reports as buried, and headings are never reported (a heading holds no place in the file's instruction order). The "position N of M" total counts only the file's instructions. A buried prohibition that names what it forbids reads "Buried prohibition"; a paid plan offers a fix for it, and for a buried vague instruction, on the same line.

- Check: `regime.triage_tier` in `-f json` takes `neutral`, `partial` or `open`. The per-file `regime` block carries only `triage_tier`; `named`, `within_capacity` and `confidence` no longer appear. Which findings a card shows as lines and which it collapses follows the grade the reply gives each finding.

- Check: a finding's `leverage` (the JSON `leverage` key, and which findings the terminal shows versus collapses) says how likely clearing it is to raise your file's displayed score: `gate_mover` is likely to, `conditional` may, `cosmetic` is unlikely to. A finding's `leverage` and the paid workflow's ordering agree. The text output does not label findings by this value. Findings carry this impact grade on a Pro run only: a free, signed-out or offline run lists findings without it, `leverage` is absent from `-f json` and from the MCP reply, and its terminal cards are not ranked. On a Pro run a finding the client reports itself, such as a missing section or a broken link, shows the grade the reply gives it, the same in the file's list as in the rewrite workflow. The diagnostics request no longer carries a per-finding gap mark; scores are unchanged.

- `ails check --heal` no longer writes a placeholder section into your file: for a missing Constraints, Commands, Testing, Project Structure or top-level-headings section it lists which file needs it and what the rule expects it to hold, so you write the content. `-f json` carries these under `suggested`, with `suggested_count` in `summary`, beside `auto_fixed`. The file it names is always the one the rule is about — your project's main instruction file for a project-wide check — and it says so when your project has no such file. A suggestion is silenced by the same `<!-- ails-disable-line <rule> -->` directive your main report honors. `--heal` with an API key the server rejected in the same run writes nothing. `ails check --heal` states that it needs an account in `--help`, and Getting Started and the FAQ say a free account is enough.

- Check: `--heal` and the formatting fix leave an unresolved `@import`, a URL with a port and `__bold__` text as written, no longer put prose names such as `JavaScript` or `PyPI` in backticks or italicise a whole bullet, and a name written in two cases is reported once. `ails check` no longer reports a prose name such as `JavaScript`, or a name inside a link, a URL or an `@import`, as unformatted code. The italic fix marks only the prohibition sentence: a line that also holds a plain instruction is no longer italicised whole, a prohibition written over several lines is wrapped from its first word to its last instead of being closed at the end of its first line, a quoted line keeps its `>` marker outside the italic, and a sentence the fix cannot place exactly is left as written. A bold label with its colon inside the bold, such as `**Note:**`, is left as written by the fix and is no longer reported as bold emphasis.

- Check: the formatting fix (`--fix` / `--heal`) backticks a whole relative path (`` `tests/unit/test_parser.py` ``) instead of only its file name, backticks a `~/` home path whole (`` `~/.claude/settings.json` ``), leaves a token inside a URL alone, and leaves a line that already carries bold or italic emphasis as it is instead of wrapping it again on every run.

- One name per kind of instruction file: everywhere the tool names a kind of file, it uses the name your agent's config gives it — `main`, `rules`, `skills`, `agents`, `plugins`, `memory`, `hooks` and so on. `ails rules list --capability` and the MCP `preflight` tool take these names and still accept `skill`, `agent`, `rule`, `subagent`, `plugin` and `hook`; `ails rules list --capability` with an unknown capability fails and lists the known ones; `preflight agent` and `preflight rule` now return the rules for subagent definitions and rule files, and `--capability skills` matches the skill rules. For rule authors, a rule's `match.type` is the config name (`skills`, `rules`, `agents`, `plugins`, replacing `skill`, `scoped_rule`, `subagent`, `plugin`), a rule that reads markdown also sets `format: [frontmatter, freeform]`, and `requires_capability` and the capabilities matrix use `main`, `rules` and `agents` (replacing `root`, `scoped` and `subagents`). Per-subagent memory files (`MEMORY.md`) keep their own `subagent_memory` type and count as memory.

- MCP `validate`: the default reply groups `workflow.listed` by its shared one-sentence explanation — several rules that carry the same explanation show it once, with each rule's title, doc link and count under it, whether or not any location is left to rewrite. `validate(path, full=true)` and `-f json` keep one row per rule with its full reason.

- Check: a broken markdown link is reported on the line that holds it, one finding per link, instead of one finding for the whole project. A rule that fails on several lines of a file lowers that file's score as one missing rule.

- Check: `CORE:C:0044` reports topic overlap between instruction files that load together and is renamed "Topic Overlap Across Elements" (slug `topic-overlap`, listed at medium severity). When a substantial share of two co-loaded files' instructions have a same-topic, same-direction counterpart in the other file, each file gets one warning naming the other by a path that starts above the agent's config folder (`.claude/skills/a/SKILL.md`, not `a/SKILL.md`), with the reason that two copies of one topic drift apart as one is edited and the other is not. The warning says how the files come to load together only where their loading guarantees it (both load at session start; or one loads alongside the other whenever it is invoked or whenever work touches its paths). Files load together when they belong to the same agent; a generic file such as a memory note pairs with any agent; a subagent definition pairs only with a session-start file. Instructions on one topic that point in opposite directions are not counted. The scorecard adds an "N element pairs overlap in topic" line for the pairs that share the most instructions. A paid plan offers a fix for each warning; a line that adds anything, or only mentions the same file, command or word, is not counted as a copy. Topic Overlap and cross-file repetition no longer count headings, repeat findings name the single-source reason (separate copies can drift into contradicting each other), and a finding repeated verbatim on one line is reported once.

- Check (text output): findings no longer carry an indented `→` fix line, and the upgrade prompts no longer promise fixes in the terminal. The terminal lists findings; the remedies reach the coding agent through the MCP `validate` tool and stays per finding in `-f json`, with the ordered remediation workflow on Pro. Without a sign-in the prompts read "sign in with `ails auth login`, then upgrade to Pro", since signing in alone does not unlock line-level detail.

- Check: the "Too brief" fix (`CORE:E:0004`) quotes the size range the check applies; an 8-token instruction flagged as too brief was previously told to expand into a range it already sat in. Instructions are no longer reported as too long; "Too brief" is unchanged. The fix names the instruction it means, "the line's too-brief instruction", and no longer repeats the word count the finding states. A grouped terminal row reads "Too brief (×4)", and a one-token instruction reads "(1 token)". The file-level "too weak to be effective" error (`CORE:C:0053`) says what makes the file's instructions weak — how many don't name a specific tool, file or command, how many are too brief, how many are written as headings, how many are hedged, most common first — and its fix follows the same list, where it previously always blamed naming. The upgrade-hint label for `CORE:C:0053` reads "weak instructions". Which findings fire, and the score, are unchanged.

- Check: advice no longer tells a prohibition to name what it forbids where that would weaken it — typically a prohibition among instructions on different topics. The "Vague instruction" warning (`CORE:C:0042`) skips such a prohibition, the file-level share of named instructions no longer counts it against the file, and neither the `CORE:C:0053` error nor its "some instructions are vague" warning counts it among the instructions that don't name one. One that does name a tool, file or command is listed as "N name what they forbid", and a paid plan offers a fix for it. The fixes for brief instructions (`CORE:E:0004`), diluted instructions (`CORE:C:0041`), bold on a prohibition (`CORE:E:0003`, which now asks to drop the bold) and an unbalanced topic (`CORE:D:0002`) no longer tell such a prohibition to name constructs. A prohibition is moved at most once, and only where the move raises the score. Scores rise for some files whose prohibitions name what they forbid.

- Check: a heading that carries an instruction (`## Never modify generated files`) is reported once, as an "Instruction in heading" warning (`CORE:S:0039`), and a paid plan offers a fix for it. It is listed in the paid workflow rather than rewritten, because a procedure's step titles (`### Step 2: Evaluate each check entry`) are reported too. A heading is no longer told to name a specific tool, file or command, and headings no longer count toward a file's vague-instruction or named-coverage findings. A bare negative heading (`## Don'ts`, `## Never`, `## Must Not`) is not reported: it labels a list of prohibitions, and renaming it would turn every item under it into an order. On a paid plan an item under such a heading is no longer advised to move out of it. The score is unchanged.

- Check: Content Dilution (`CORE:C:0041`) no longer proposes moving same-topic prose to another section. The finding, and **Specificity Shields Against Competition** (`CORE:C:0050`), is reported on each same-topic context item, naming the instruction it sits near; a heading or a fenced block is never among them. On a paid plan both are listed for you to decide on instead of being trimmed in the rewrite, because how much same-topic prose weakens an instruction depends on the model your agent runs on; their messages and rule pages say so. A rewrite that deletes prose whose content appears nowhere else in the file fails the `preservation` check. The scorecard counts them as "excess context" and "context near vague". The unbalanced-topic finding (`CORE:D:0002`) points at the weaker side.

- Paid remedy: the advice on a too-brief or vague instruction no longer asks for anything the instruction does not already say. It names what the instruction already refers to, asks for no condition, timing or scope the author did not write, and leaves an instruction that is not about code as it stands. Advice on a hedged instruction recommends a direct instruction ("do not") rather than an absolute one ("never"), and the Modality Weakness rule page no longer shows `NEVER` or `ALWAYS` as the stronger form. Italic on a prohibition is described as a convention, not as something that strengthens it.

- Paid remedy: the `preservation` check after a rewrite also fails when a bare negative heading such as `## Don'ts` was renamed or removed (`relabelled_negative_headings`), and when an instruction gained a condition its original did not have (`added_conditions`, for example an added "whenever …" or "before every commit"). The rewrite contract says to keep such a heading exactly as it is. A heading that carries an instruction (`## Never push directly to main`) now counts as an instruction of the file: a rewrite that renames it without keeping the instruction, or that turns it around, fails the check, and the brief marks such a heading with its `polarity`.

- Check: **Agent Documents Filenames** (`CORE:S:0012`) checks the project's main instruction file instead of every rule file, which had no reason to list instruction filenames; in the paid workflow it is listed as a documentation convention for you to decide on. Its example names the files every agent reads in a shared `AGENTS.md`, which Cross Agent Compatibility (`CORE:C:0026`) also accepts, and Cross Agent Compatibility no longer checks Copilot's own `.github/copilot-instructions.md`.

- Check: a content check that forbids something, such as a prohibition not written in italics (`CORE:E:0006`), reports the file and line where it found it; it reported line 1 of the first file it checked.

- Check: `CORE:C:0013` (project description) accepts a description written directly under the title — a paragraph, blockquote or list of five or more words before the first section heading, as long as it is not itself an instruction. It previously required a heading named "Description", "About" or "Overview".

- Check: the broad conditional scope check reports under its own rule, **Broad Conditional Scope** (`CORE:C:0060`), which replaces the retired `conditional-scope` core rule, and fires only on scopes that name external services, third-party integrations, dependencies on outside systems or database and SQL code, not on "any file" or "all tests". The broad-term match is whole-word, so `all` is no longer read out of `intrinsically` or `calls`. An instruction that carries a condition (`If the tests fail, do not push.`, `Only for <X> files`) is recorded as conditional again, which the branching-procedure check (`CORE:C:0039`) and this check depend on. The ambiguous-phrasing finding (`CORE:C:0059`) and `CORE:C:0060` have their own rule pages, so `ails explain` resolves them.

- Check: the hard-coded credential check fires on a real `secret_key` value, including one that starts with a symbol, and no longer fires on a documented field such as `secret_key: str`. A reference to a secret is not reported as one: an environment-variable reference (`$NAME`, `${NAME}`, `%NAME%`, `{{ name }}`), a placeholder such as `<ask the lead>` or `YOUR_PASSWORD`, emphasis, and a YAML block marker.

- Check: project-wide checks (the two-file minimum, the total size limit) run once over the whole project when several agents are detected, in `ails check` and MCP `validate` alike, so a finding is not reported once per agent. On such a run every agent's own findings are scored, so a broken hook or another agent-specific defect counts toward the score and the paid fix workflow as it does with `--agent`, and the total size limit is not repeated on a file that an agent's own stricter size rule already judges.

- Check: instruction files are found regardless of filename case (`claude.md` == `CLAUDE.md`, `agents.md`, `gemini.md`); a project whose only instruction file was `claude.md` used to report no agent. `ails check <path>` on a project checked from a parent directory scans it as its own project instead of the whole parent directory, and `ails check <file>` from another folder uses that file's own project; checking a file or folder without `--agent` detects the agent in the checked path's own project and no longer scans the folder the command is run from; a looping symlink among the files no longer stops the check. Checking a single file or part of a project no longer crashes with a `TypeError`.

- Check: a directory inside the project is scoped from the project root and narrowed to its subtree unless it is itself a project root (`.ails/`, or an agent main file plus that agent's config folder). `ails check .claude` no longer reports only a stray `.claude/CLAUDE.md`, and `ails check .claude/skills` scores the files under it and matches `ails check skills` file for file, instead of reporting an empty result at exit 0. `--strict` on such a directory with findings exits 1, and `--heal` on one has files to fix.

- Check: `ails check <folder>` on a folder holding only a `CLAUDE.md` or `AGENTS.md`, run from outside that folder, checks it as its own project instead of reporting "No instruction files found" and passing `--strict`; a folder inside a larger project is still checked as part of that project. Under `--strict`, a key the server rejects fails the run even when the checked files have no findings.

- Check: reading instructions is more accurate in the following cases, so the findings and scores that follow from them change on files that hold such lines.
  - What counts as an instruction. A line that is plainly not an instruction — a `See:` cross-reference, a bare `No <noun>` status line, a quoted string, a past-tense or first-person narration (`We shipped the fix`), a bare section label — stays neutral. A heading that only names its section (`Step 2: PRD Structure`, `What to avoid`) is not an instruction, and a heading that gives one takes its place in the file's order. A `No …` line that names what it forbids is a prohibition (`No console.log`, `No hardcoded secrets`, `No blank lines between sections`) and stays neutral only as a one-word count, a named status report or a described absence. A line fronted by a label, pointer or status fragment keeps the instruction that follows it (`**Important** — always run the tests`, `See docs/testing.md, and never skip the integration tests`), and a line that is only the label stays neutral. A sentence that opens with a quoted term is read as running text and keeps its instruction, while a whole-line quotation stays one quoted example, however many sentences it holds. An instruction written with "should" is reported as hedged. A word or phrase that gives no action of its own — a joining "Or", a subject before "must …" — is read with the instruction it belongs to. A bold label before a dash or colon no longer draws "Bold on a prohibition" or "Bold on terms", and titles the instruction after it instead of counting as an instruction of its own. A task list's checkbox is not counted as words of its item. A colon line whose left side is a clause (`Never commit secrets: see security.md`) keeps its instruction.
  - Lists and tables. An instruction that ends with a colon and introduces a list of things (`Audit these files:`) is read together with its list, so it is no longer flagged too brief or vague; a list of commands stays one instruction per command. A list item under a prohibition heading (`## Don'ts`, `## Must Not`, `## Never`) is read as a restriction; a positive or neutral heading carries no such force. A table row is read as one line with its cells joined, so `| Rebuild step | Always run the generator before commit |` counts, and a Do/Don't row reads as two instructions. A header row and placeholder rows are not instructions. A semicolon-chained prohibition list (`do not A; B; C`) keeps its prohibition across the whole chain. A numbered list item stays whole.
  - Fenced blocks and code. An instruction inside a fenced block — a `Never …` or `Always …` in a rule file — is scored like the prose around it, including one written with emphasis or backticks, and no longer draws the bold, italic or unformatted-code findings. A fence tagged as code or a diagram (`python`, `json`, `mermaid`), one whose body is JSON, TOML or Python, and one whose lines are mostly shell is left out as code; a fence tagged `markdown` / `md` is a demonstration and left unscored; an untagged or `text` fence that holds instructions, a table or prose is still read line by line. A report template or file sample written in a fenced block with markdown headings, a tree or layout diagram row, a fenced flow diagram, and a backslash-escaped fence are not read as instructions, and neither is an indented code block or a run of box-drawing characters.
  - Content that is not instructions. A YAML configuration block written in an instruction file (such as a skill file's `progressive_disclosure:` settings, including an unclosed one at the end of the file), a Cursor rule file's second frontmatter-style block, and concatenated repo-dump scaffolding (`====` with a `File: <path>` header) are no longer read as instruction text. A reference to a non-markdown file (an image, PDF, archive) is no longer spliced into instruction text, and a file referenced twice expands at both references. A section that opens with a `---` divider and a label line is no longer erased, and a longer `----` divider no longer hides the rest of the file.
  - Splitting. Two instructions on adjacent hard-broken lines no longer merge into one. A line that packs unrelated subjects is split into one instruction per clause. A sentence already split into instructions is not cut again at `when …` / `because …` / `— …` clauses, which produced fragments that surfaced as "2-word instruction" and vague-instruction findings no edit could clear. Sentence boundaries are found correctly around quotations, symbol-led text, identifiers (`.claude/rules/`, `yaml.YAMLError`, `.env.*`), paths, globs, versions, file references, code punctuation (`?.`, `git add .`, `INSERT ... VALUES`) and malformed tables; an instruction that starts on a lowercase code name starts its own unit; emphasis around more than one sentence leaves no stray `*`.
  - Words and names. Names containing underscores or asterisks (`my_module.py`, `*.pem`) are kept as written, a backticked name counts as the words it holds (and never as emphasis), emphasis around a snake_case name is recognized, and combined bold and italic is kept. Emoji, pictographs and box-drawing characters in instructions and headings are ignored, and a unit with no word in it (`» » »`, `1. 2. 3.`) is not analysed as an instruction. An uncommon command verb at the start of an instruction is read as an instruction.
  - Consistency. Every word of an analysed line lands in some instruction, the end of a very long sentence no longer takes the direction of an earlier instruction, a one-instruction file no longer produces an empty topic position, two files with identical content score the same, a fenced block in a file with frontmatter reports its true line number, a cached result carries the same data as a fresh one, and position-based findings fire for every file in a project rather than only the first. A finding on an instruction brought in by an `@path` import names the imported file, its line and the instruction, a finding on a line after an import reports your own line number, and an `ails-disable-line` after an import silences its finding again.

- Check: the `CORE:E:0004`, `CORE:C:0047` and `CORE:C:0053` rule texts match what their checks measure (`CORE:C:0047` describes weight rising steadily toward the end of the file; `CORE:C:0053` no longer names a "15-50 distinct terms" target), and their Pass examples pass their own checks. `content-dilution` (`CORE:C:0041`) no longer claims off-topic content is harmless regardless of volume, `position-recency` (`CORE:C:0047`) states that the position penalty applies to abstract, unnamed instructions, and `related-instructions-grouped` (`CORE:E:0005`) asks to group by topic rather than co-locate everything. `explicit-prohibitions` states that a prohibition inside a fenced block that reads as an instruction is counted, while one inside a comment or code block is not. Instruction Ordering's (`CORE:D:0003`) own Fail example draws the finding it describes. Rule pages and check messages use plain words, and `ails explain` for Position Recency and the Codex skill-metadata rule describes the problem without repeating the paid fix. No rule id, severity, check or score changes from these text edits.

- Rules: eight section-presence checks on the main instruction file are now warnings instead of errors: security requirements (`CORE:C:0011`), coding conventions (`CORE:C:0012`), project description (`CORE:C:0013`), agent role (`CORE:C:0014`), domain terminology (`CORE:C:0024`), output format (`CORE:C:0025`), architecture overview (`CORE:C:0033`) and tech stack (`CORE:C:0034`), matching the six checks of the same kind that already were. Which findings fire is unchanged; they drop out of the error count and the "Fix now" line.

- Rules: severity changed across the core ruleset. Specificity rules are now critical, instruction-direction and topic/scope rules high, and position, length, inline-formatting and dilution rules low. Low-severity findings display as `info` instead of `warning` in text, JSON and MCP output; the set of findings is unchanged. A per-check `severity:` in `checks.yml` carries through to deterministic findings. Example blocks and guidance text no longer model patterns that weaken the instruction they illustrate (prohibition examples use sentence-case negation and abstract categories).

- Check (summary): the check summary reads in three lines — `Quality` (the score), `Fix now` (the error count and the rule with the most errors, to start with) and `Findings` (one total). The raw error/warning/info headline is gone from the text output; those counts stay in the JSON `stats`. The per-surface and per-item health bars read `N findings · M errors`, and the file-card tail reads `+N more · -v to list`. On the free tier the `Fix now` line names the errors held back as Pro diagnostics beside the visible count. The scorecard's upsell lines key on whether an API key is held: a signed-in user is pointed at the upgrade page and a keyless one at sign-in.

- Check (JSON output): `cross_file[].type` and `cross_file_coordinates[].type` can be `overlap` (one shared instruction of an overlapping file pair), `stats.cross_file_overlaps` counts the overlapping pairs, and the repetition count is one number at every tier (`stats.cross_file_repetitions`), which the text scorecard also reads. Cross-file repetition is reported once per repeated line pair, and `cross_file` rows name files by project-relative path.

- Rate limit: once the hourly limit is reached, the CLI waits for it to reset before checking again; runs in the meantime show the same limit message with "Try again in ~N min" counting down, so a watcher, hook or agent loop no longer keeps hitting a limit already reached. Signing in with `ails auth login` applies your account's own limit straight away.

- Install and first run: the package no longer includes the analysis model, so `pip` and `npx` installs are much smaller (under 10 MB instead of ~241 MB). The model (~275 MB) downloads once per machine, on the first `ails check` that has instruction files to check, into `~/.reporails/cache/models/`, with a `Downloading reporails model…` line on stderr; every later run works offline. A mistyped path downloads nothing, a slow first download is not cut off by the check's time limit, checks started at the same time download the model once, and a check waiting on another download carries on by itself if that download stops making progress. If the download host cannot be reached, `ails check` stops with a clear error and exit code 2, and MCP `validate` reports the model as unavailable. A damaged or partial download is never used and never stays in the cache; a model file that later goes missing or is damaged is restored on the next run, and the check only fetches the files it uses. The cache keeps the current and the previous model version. The model downloads without an account (when you are signed in, the download carries your API key). `AILS_MODEL_URL` points the download at your own mirror (your key is never sent there), and `AILS_MODEL_OFFLINE=1` never downloads: it uses a model already on disk and otherwise runs without the content checks, saying so. The MCP server starts the download when it launches. No change to findings or output.

- Install: a fresh install is lighter — it no longer pulls `scikit-learn` (or `joblib` / `threadpoolctl`) or `spacy` with its language data, and two other runtime dependencies are gone. Analysis results are unchanged.

- Rules ship inside the package and update when you update the CLI (`ails update`); the leftover code for a separate rule download and a startup update check is removed, and the `auto_update_check` setting, which never had an effect, is gone from the docs. `ails install`, `ails update`, `ails version` and rule loading are unchanged. After `ails update`, the next check re-reads each file's agent, load timing and scope; the first check of each project after upgrading to this release is a full cold analysis.

- Check (speed): checking many projects in a row no longer reads and rewrites one large cache file each time; each run reads and writes only the entries for the files it checks, identical files share one entry across projects, the least recently used entries are evicted, your existing saved analyses carry over on the next run, and entries from an older model or cache format are removed. A repeat check with no file changes returns the finished analysis instead of redoing the work, and editing, adding or removing a file rebuilds it. A damaged saved analysis is rebuilt instead of used. A cold first check is faster: the analysis runs across CPU cores and over all of a run's files at once, loads the model once, and gives identical output at any thread count (`AILS_ORT_THREADS` sets it). An analysis cache written by a different CLI version is reused where it can be instead of crashing or forcing a full re-analysis. Large repositories now complete where they previously hit the size limit and fell back to offline results.

- Check progress: while analysing, the spinner advances per harness element (`Mapping agents: 2/14`, `Mapping skills: 5/15`) and then per instruction (`Analyzing instructions: 283/1023`) instead of sitting on one line that read as stalled, on cold and warm runs alike. A cold run that has to start the background helper shows `Starting Reporails...` → `Loading tools...` → `Reporails ready`. The phases after analysis read `Checking rules...` → `Running content checks...` → `Diagnosing...`.

- Tiers: the self-serve tier model is binary — `free` and `pro`; a legacy trial tier recorded earlier reads as `free`, and the free and anonymous tiers share the same 2 MB size limit. Pro is a subscription started from your account page at reporails.com, where a promotion code, if you have one, can be entered at checkout; the CLI itself has no billing step. A rate- or size-limit rejection shows the call to action that matches the key the CLI holds: a signed-in user with no active subscription is pointed at the upgrade page (or the server-provided link), never back to `ails auth login`; an anonymous run is given the two real steps in order — sign in, then upgrade to Pro. The atom-count and file-count limits are the same for every plan, so their messages carry no upgrade promise; the free and anonymous size-limit message names Pro's 20 MB cap. An older CLI gets a message to run `ails update` instead of a score, while its local checks keep working.

- Check / MCP `validate` (paid workflow): on a large project the reply's locations to rewrite are no longer cut to two or three items while the summary counted dozens more, each element's fixes stay together, and a topic with no dominant direction is counted as its own topic instead of failing the whole request.

- `ails explain`, MCP `explain` and `ails rules list` show every match setting a rule uses (`content_format`, `loading_verb`, `link_source_type`, …). `ails explain` shows the rule's whole body, antipatterns and limitations included, instead of cutting it at 500 characters, prints the Pass / Fail examples once in their own block, shows the rule's own severity and each check's real severity (not `medium` for every check), says when a rule runs on the server, and shows a rule's category and type.

- `ails install`: the unused positional `path` argument and the deprecated hidden `setup` alias are gone; bare `ails install` is unchanged.

- Cross-agent delivery via the reporails plugin: the `ails` skill and the reporails MCP server ship as a portable Agent Plugins package instead of being written per agent by `ails install`. Installing the plugin registers the MCP server (`validate` / `remedy_brief` / `preflight` / `explain`) and loads the `ails` fix-loop skill in all five supported agents — Claude, Codex, Cursor, Copilot and Antigravity. `ails install` no longer writes per-agent MCP config files or copies the skill into per-agent folders: it makes sure the CLI/MCP engine is on PATH (at least the version you ran, so a later `ails update` still moves it forward) and prints the plugin-install command for each agent. Agent Support lists the same commands and what the plugin needs to start: `uv` on the machine, and network access for its first start, which downloads the CLI and the model files.

- Config: the retired model-selection setting in `.ails/config.yml` and `~/.reporails/config.yml` is ignored without an error, and findings, scores and output are unchanged. `ails config set tier` and `--global tier` report an unknown key (tier is resolved by the server from your subscription, so a local key could only mislead). The `overrides:` key (per-rule `severity:`) is removed — it was parsed but never applied, so a rule's severity comes from its rule file; set the per-rule `min_lines` threshold with the top-level `rule_thresholds:` key (the docs showed it under `overrides:`, where it was ignored). The unused `framework_version` key is gone.

- `ails test`: a malformed `checks.yml` entry fails with an error instead of loading silently. `ails test` checks each rule's content checks against the rule's own pass and fail fixtures, through the same evaluation `ails check` uses, so a fixture that no longer proves what it claims, or a check that never fires, shows up as a failure; every content-checked rule now has a pass and a fail fixture taken from its documented example. A bare `ails test` runs the bundled rules, runs a rule's inherited checks against its fixtures and names the main file after the agent under test. `ails test` remains a local rule-authoring command. An invalid `checks.yml` is reported by file and reason, that rule counts as failed and the run carries on, instead of ending in a traceback.

- `ails test` also runs each rule's `tests/cases/pass-…` and `tests/cases/fail-…` fixtures, names the case in its output, and lists any other case folder as not run.

- `ails check` no longer rejects a project on your machine using a guessed size limit; an oversized project still gets the same too-large message from the server (`payload_too_large` in `server_error`). The local limits on instruction count and file count are unchanged.

- MCP server: `validate` and `preflight` return their result as structured content that clients can read directly, alongside a compact text copy. `explain` stays plain text, and every tool is marked read-only. The tool set, inputs and response payloads are unchanged.

- Rule schema: the rule schema documents the check fields rules actually use — `pattern-regex` / `pattern-either` / `patterns` (with `pattern-not-regex` inside `patterns`) — instead of a single `pattern:` that was never recognised, so a rule written to the old schema never fired. It also lists five shipped mechanical checks it was missing (`extract_markdown_links`, `check_markdown_link_targets_exist`, `frontmatter_matches_dirname`, `skill_entrypoint_present`, `glob_match`), the list form and every value of `match.type`, and `min_lines`. The schema documents `fix:` as retired from public rules. No rule behaviour changes.

- Agent capability matrix refreshed against the vendors' current docs, which changes which capability-specific rules fire per `--agent`: **codex** gains `output` (its `personality` setting is output-style customization), **cursor** loses `output` (its `--output-format` is data serialization, not persona or style), and **antigravity** gains `scheduled_tasks` (native `/schedule`). Claude and Copilot are unchanged. The Agent Support page matches.

- MCP `validate` reports the same memory-index validation and capability level (L0–L7) as `ails check`, so a project with a broken `MEMORY.md` link surfaces that finding under `validate` (it previously passed silently) and the response carries the computed level. It reuses the same warm analysis as `ails check` instead of loading the model cold on every call, so a repeat `validate` on an unchanged project returns from cache, and it discovers files the same way the CLI does — same agents, same excludes, same inline `ails-disable-line` suppressions and surface-scoped rule mutations — so a multi-agent project validates the same file set on both surfaces.

- MCP `validate` returns a bounded reply by default — the top findings per file plus every aggregate field (`stats`, `surface_health`, `level`, `tier`) whole — so validating a large repo no longer overflows the tool-result size cap. Each file keeps its true finding `count`, and a `truncated` block names how many findings were omitted. Pass `full=true` for the complete finding set; calling again with `full=true` right after a bounded reply returns the already-computed result. The bounded reply also keeps the line-pair `cross_file` rows behind `full=true` when a workflow is present and keeps the first 25 otherwise (`truncated.cross_file_shown` / `cross_file_total` say how many were left out), caps the listed locations, and keeps every total and count whole.

- `ails check --format`: an unknown value is rejected with a usage error (exit 2) naming the formats that exist — `text`, `json`, `github` — instead of silently falling back to the scorecard. The formats retired this release (`compact`, `brief`) therefore error. `ails rules list`, `rules agents` and `rules capabilities --format <value>` reject an unknown format the same way.

- `ails check` text banner: the tier badge comes from the tier the server answered with (`pro`/`team` → `Pro`; `free`/`anonymous` → no badge; offline → `offline`), so a retired legacy tier string in `~/.reporails/credentials.yml` no longer forces "Pro (beta)" onto every run. `ails auth status` prints `free`/`pro`/`team` when that is what is on disk and "(resolved at check time)" otherwise, and both `status` and `token` honour an `AILS_API_KEY` environment override (it wins over the stored credentials file, as in `ails check`): `status` names the key source, `token` prints the effective key, and `logout` never modifies the environment and says so.

- `--format json` and `--format github` carry a `server_error` object (`status`, `error`, `message`, `tier`, `upgrade_url`) when the diagnostics server rejects a request, times out or is unreachable, instead of reading identically to a designed offline run. A CI `min-score` gate no longer goes green on an outage, and the GitHub Action reports `result=server-unavailable` with the reason. MCP `validate` reports `offline: true` with `server_error` filled in for the same run. With nothing in scope (an empty project, a config-only project, or an `--agent` filter that matches no file), `-f json` / `-f github` and MCP `validate` emit the same top-level envelope a normal run does (`quality: null`, `level: "L0"`, `files: {}`, zeroed `stats`) instead of a second, smaller shape.

- `--format github`: the trailing JSON summary is the same document `--format json` prints (so `surface_health[].file_count` no longer collapses to "files that produced findings"), and `info`-severity findings render as `::notice` instead of `::warning`.

- GitHub Action: caller inputs (`path`, `strict`, `agent`, `exclude-dir`, `version`, `from-source`, `min-score`) and the check score reach the shell and Python steps only through quoted environment variables. With `server-url` left at its default the action checks against the reporails server instead of running offline, so the score, a Pro `api-key` and the `min-score` gate take effect, and an empty `AILS_SERVER_URL` means the default server. The `min-score` gate fails closed when the server rejected the run, timed out or was unreachable, and two new outputs, `server-status` and `server-error`, expose the reason. The `level` output range is documented as `L0-L7`.

- Check: a rule that targets files by `loading_verb` or `link_source_type` applies to just those files (both were ignored, so such a rule matched every file), a content-quality rule whose `match` names any criterion no longer falls back to every mapped file when nothing matches, and a rule whose `match.type` is a list finds its files in mechanical checks too. Prose rules no longer score JSON and TOML, so `ails check .mcp.json` does not report missing section headers and `ails check hooks` on a real settings file reports only config-surface findings.

- Check: `.claude/settings.json` and `.gemini/settings.json` are read as config files, so the rules that target the config surface — every hook rule and per-agent hook overlay, plus the permission, MCP-server and settings-scope rules — no longer stay silent on the main settings file. Hook rules also target a dedicated hooks file (`.cursor/hooks.json`, `.codex/hooks.json`, `.github/hooks/*.json`), covering 25 rules across all five supported agents. Machine-config surfaces that are neither JSON nor TOML (`.codex/rules/*.rules`, `agents/openai.yaml`, `.gemini/extensions/**`) are recognised as config, so prose-quality rules no longer fire on them.
- Check: the summary's topic-overlap lines name each side as its element — `name (skill)`, `name (agent)`, `name (rule)`, `/name (command)`, `name (memory)` or a short path — one aligned line per element with up to three partners, and count element pairs; two that share a name are told apart by location, and overlap between files of one skill is not counted as a pair. Each file shows its topic overlaps once under its name, one row per partner (`38% topic overlap with audit-agent (skill)`), instead of under a line number.
- Check: when a project is too large for the server to score in one request, the message says so and suggests checking a smaller part, instead of asking for a bug report.

### Fixed

- Check: Hook Uses Project Dir Variable (`CLAUDE:G:0001`) accepts a plugin's hook that finds its script through `${CLAUDE_PLUGIN_ROOT}` or `${CLAUDE_PLUGIN_DATA}`, as the Claude Code hooks documentation directs. A plugin's `hooks/hooks.json` written that way is no longer reported, and heal no longer asks to replace that path with `$CLAUDE_PROJECT_DIR`.
- Check: an instruction file is found only under the name its agent opens. On a case-sensitive filesystem, where Claude Code and Codex open `CLAUDE.md` and `AGENTS.md` only under that exact spelling, a lowercase `claude.md` or `agents.md` is no longer checked as an instruction file and no longer raises the Level line. On a case-insensitive filesystem (macOS by default), where the agent opens it, it is found, checked and listed as `CLAUDE.md` or `AGENTS.md`. A rules file that happens to be named `claude.md` (`.claude/rules/claude.md`) is still checked as a rule.
- Heal: the rewrite check no longer reports an unchanged instruction as narrowed when one backticked name sits inside a longer one on its line (`reporails` beside `reporails__explain`). A location holding such a line can now pass instead of being restored on every check.
- Check: a folder in a skills folder that has no `SKILL.md`, reported by Skill Entry Point Present (`CORE:S:0015`), now shows under Skills: it counts on the Skills row in the terminal, `--format json` and MCP `validate`, and `-v` lists it with the skills instead of among plain files. The other files in that folder stay plain files, since no agent loads them as a skill.
- Check: Skill Entry Point Present (`CORE:S:0015`) looks only at the folders an agent loads skills from, so a folder beside a skills folder (such as `.cursor/rules`) is no longer reported as a skill missing its `SKILL.md`, and a Cursor category folder that groups skills is not flagged.
- A check the server refuses for a known reason (a rejected or malformed key, the hourly limit, the payload cap, the project limit) no longer asks you to report a bug; the bug-report link shows only for an error the CLI does not recognise.
- Heal: a CRLF or mixed-ending file keeps each line's own ending, a file holding a form feed or a Unicode line separator has the right line fixed, a token inside an inline HTML tag (`<img src="logo.png">`) or an autolink is left alone so a second run changes nothing, and a file with hundreds of code tokens or bold constraints heals in under a second instead of over a minute.
- Check: a link after a code span that runs onto the next line is reported on its own line, an `ails-disable-line` comment after a form feed or Unicode line separator silences the line it sits on, a rule's path filter with a `{a,b}` group matches the files its alternatives name, and a paragraph of thousands of nested bold or italic runs is read in seconds instead of minutes.
- Check: `ails check <folder>` run from a folder above it checks that folder's own agent rules and skills, with paths relative to it, even when the folder has no `CLAUDE.md` or `AGENTS.md`; a line after a code span that runs onto the next line keeps its true line number, and a form feed or Unicode line separator inside a fenced block, or in the file text the MCP tools return, no longer shifts the lines after it; a bare URL in running text is read as the URL itself, so bold, italic or an escape around it no longer becomes part of the link.
- Heal: a path wrapped in backticks is no longer joined to a code span right before it (`` `src`/main.py `` becomes `` `src`/`main.py` ``), bold that touches another bold or italic run is left alone so the two no longer merge into one italic, and turning bold around a URL into italic is no longer refused as a removed link.
- Sign-in and limits: when an account is already enrolled but this machine has no key, `ails auth login` says to generate a new key on the account page and set it as `AILS_API_KEY`, instead of "contact support or re-register"; the hourly-limit message names what Pro gives (1,200 checks an hour) instead of "40x".
- Check: `ails check child_instruction`, `ails rules capabilities` and heal no longer pick up instruction files inside `node_modules` or the other folders every check skips; a link whose address or title continues on the next line no longer shifts the line numbers after it; a rule's path glob is checked against the project's own files, so a leading `/` means the project root and a glob that matches only inside `node_modules` or another excluded folder, or reaches outside the project with `..`, is reported as matching nothing; a comma-separated `applyTo` or `globs` filter is read as separate globs everywhere; and the path-glob check no longer slows down with the number of rule files.
- Check: a file is checked as a memory note only when it is one, not because its folder name contains "memory"; an empty or list-shaped memory frontmatter block reports the missing name, description and type; a Claude project whose path holds an underscore or a dot finds its auto-memory; a file that is not UTF-8 gets the markdown, import-depth and forbidden-pattern checks instead of a traceback, and an `ails-disable-line` comment in it silences its findings; a form feed inside a rule's path filter no longer stops the filter from being read; and a config-style block after a line that only looks like a code fence is read.
- Heal: a file that is not UTF-8 is left unchanged with one line saying so, instead of a traceback; a correct rewrite is no longer refused as dropping a condition when it wraps a word of the condition in backticks, backticks a name such as `try`/`except` or `if`, or names the object of an "only …" instruction, while a rewrite that widens an exception (`except integration tests` → `except slow integration tests`) is still refused and a backticked code word such as `except` never makes an instruction read as conditional, while an added restriction that reuses a word from inside a backticked path or command is still flagged; and the check of a rewrite no longer reads text from another project whose folder name starts the same.
- Check: a rule, skill or agent file that starts with a byte-order mark is read with its frontmatter, a file that is not valid UTF-8 no longer prints a traceback, a frontmatter that opens with `---` and never closes is reported once ("the frontmatter block is not closed"), and a skill or agent whose frontmatter is a list or a bare value is reported once, not also as missing `name` or `description` (an empty `name:` or `description:` still counts as missing).
- Check: a rule's `paths: src/**/*.{ts,tsx}` is no longer reported as two globs that match no file, and a rule's dead glob is looked for in the key its agent reads (`paths` for a Claude rule), not whichever of `globs`, `paths` or `applyTo` came first.
- `ails explain` no longer prints a rule page's frontmatter when its first line is a comment, the `valid_markdown` check no longer reads `#123` inside a list item or a quote as a broken heading, and a file whose constraint lines say `IMPORTANT` counts as stating explicit constraints.
- Rewrite check: a rewrite that only reorders joined conditions ("the build or the tests" → "the tests or the build") is not reported as dropping one. A running MCP server picks up an edit to `~/.reporails/config.yml`, and a circular symlink named like an instruction file is skipped with a warning again.
- Heal and the bold check: bold written inside a code span or a link target is neither reported nor rewritten, `***both***` is left as it is so a second run changes nothing, and a sentence whose stars are a glob pair or that sits inside a bold run is not wrapped in italic.
- Check: a rule whose path filter is written unquoted (`paths: **/*.ts`, Cursor `globs:`, Copilot `applyTo:`) is read the way the agent reads it and is no longer reported as having broken frontmatter, and a frontmatter that is not valid YAML is reported once, by its file type's frontmatter rule.
- Check: an `AGENTS.md` beside a `CLAUDE.md` is checked too; before, it was checked only when another agent's files happened to claim it.
- Check: italics, bold or a link around an instruction no longer count toward its length, so a short prohibition stays short whatever its styling.
- Check: a Cursor rule's loading is read from the current rule file after an update, not from a map cached by an earlier version (one slower first check after updating).
- Rewrite check: padding added after a fenced example that itself shows a bare fence line is now reported.
- Rewrite check: it fails a hedge turned into "Never" or "Always" when the line did not already say so, a restriction added without an if / when / before (a place, a day, an "only"), a condition the rewrite removed, and a file padded with copies of its own lines.
- Docs: the Instruction Elaboration rule page's Pass example no longer carries a timing.
- Check: a busy diagnostics server, a request that takes too long and a request the client gives up on each print one plain line saying to try again in a number of seconds, with no invitation to report a bug; the JSON and MCP error messages say the same.
- Check: `ails check` started from inside an agent's configuration folder (`.claude`, `.claude/rules`) checks the project that holds it, as naming the folder from elsewhere already did, instead of reporting no instruction files. A Cursor rule with `alwaysApply: true` is treated as loaded in every session whatever its `globs`.
- Check: an offline run reports an instruction in a heading (`CORE:S:0039`) in every instruction file it reads, including agent and skill files in nested folders; before, those files' headings were reported only when the diagnostics service answered.
- Check: a misspelt hook event name is reported once, on its own line; the line that opens the hooks block is no longer reported beside it. A reply from the diagnostics service that is not a JSON object, or that holds entries that are not objects, is reported as an unavailable service or skipped instead of ending in a traceback.
- Cache: opening the cache under one configuration no longer deletes the warm cache of a project that uses another; a configuration's cached maps are removed after 30 days without use.
- Messages: when a project is refused for holding too many files, the message states the project's file count instead of 0.
- MCP: `validate` notices an edit that keeps a file's size and modification time, and a server address changed during a session, instead of serving the earlier reply. `remedy_brief` asked for a part outside the brief answers with an error that names the valid range, and every part stays under the stated size unless a single item is larger than that size on its own. A rewrite brief for a large instruction file comes in a handful of parts instead of hundreds; no part is empty, and the line fixes of a brief are spread over its parts. When the rules folder is missing, the reply says what is missing and what to do about it.
- Check: a Codex fallback instruction file named under `agents.codex.fallback_filenames` is listed, checked and scored where Codex reads it: in a directory with no `AGENTS.md`, at the project root or in a subfolder, also when it is the project's only instruction file and also with `--agent codex`. A fallback file beside an `AGENTS.md` is not read by Codex and is not checked.
- Model: with only part of the model on disk and `AILS_MODEL_OFFLINE=1`, a check reports that it ran without the model and shows no score and no content finding, where it used to show a score made without the model. A cached model file that was damaged in place is noticed at the next run and fetched again. A run no longer writes a file into the installed package folder. `ails test` fetches the model the way `ails check` does, and stops with a short error instead of a traceback when the model cannot be had.
- Heal: the italic fix leaves a line that opens with an unpaired `*` as written instead of doubling the mark, and the bold fix leaves a list line that is bold from end to end. The preservation check reports a prohibition appended to an existing line as an added instruction unless one sentence of the original already says it.
- Check: a misspelt hook event name next to a valid one is reported for Copilot and Cursor hook files, as it already was for the other agents. The backticks finding (`CORE:E:0003`) quotes a name as it is written in the file (`Django`, not `django`), and one name on a line draws one finding (`settings.json`, not `json` as well).
- Check: `ails check .claude` (an agent's own configuration folder) checks the project that holds it, so the project's rules and skills are no longer dropped; and a project below a home directory that is itself a git repository is rooted at the project, not at the home directory.
- MCP `validate` on a rewritten file: the `feedback` list now also names a problem the rewrite itself introduced (a finding whose rule was not reported on that file before), listed first, errors ahead of the rest. A key pasted into the file by a rewrite is no longer hidden behind the file's earlier findings.
- Check: a Cursor `.mdc` rule file has a valid file name (`CORE:S:0014`); a Cursor rule without `alwaysApply: true` is treated as loaded on demand, not in every session; the italic rule (`CORE:E:0006`) no longer runs on an agent's configuration files; and a Claude or Cursor rule file is no longer asked for an `id`, `name` or `slug` its agent does not define (`CORE:S:0005`).
- Check: the credential rule (`CORE:G:0002`) reports a key written anywhere in a line, not only as an assignment (common API-key, token and access-key shapes, and private-key headers), reports every line that holds one in a single run, and reports a key inside a file that an instruction file imports, on the imported file's own line. A parameter or field declared with a type and no value (`password: string`) is no longer reported, and obvious placeholders are left alone. Any rule that forbids a pattern now reports each line that has it instead of the first one only.
- Check: a circular symlink named like an instruction file no longer stops the check with an error: the link is skipped with a warning and the rest of the project is checked. A tool name that appears only as the text of a markdown link is no longer reported as code that needs backticks (`CORE:E:0003`); the same name written bare on another line still is.
- Check: every prohibition that is not in italics is reported on its own line (`CORE:E:0006`), and every heading that carries an instruction gets one "Instruction in heading" warning (`CORE:S:0039`) that quotes the heading. Before, only the first of each in a file was reported by the rule, and later headings were listed at a lower level in different words. "Flowcharts for Procedures" (`CORE:C:0039`) is reported for each file it applies to. An inline ignore that names `heading_instruction`, the rule id or its slug still silences the heading finding.
- Heal: `ails check --heal` and the MCP remedy brief leave an agent's settings, hook, MCP and plugin config files exactly as written; the backtick and italic fixes apply to instruction files only.
- Heal: the backtick and italic fixes find code, links and plain paragraphs through the markdown parse, so text inside a longer code span, a reference link's label or definition, a longer fence or an indented code block is left alone.
- Heal: the bold-to-italic fix leaves a line that is bold from end to end after a blockquote or list marker (`>`, `> >`, a quote inside a list item, `1)`, a tab after the marker) as it is, and no longer changes bold inside a fenced or HTML block.
- Check: a line that opens with a command in a double-backtick code span followed by a dash or colon is read as a command reference, like one in single backticks, and a stray backtick before a number no longer marks a line as a version note.
- Findings: a line you silence with `ails-disable-line` does not raise the impact tier shown on the same file's other structural errors.
- Findings: a One Instruction Per Sentence finding (`CORE:C:0058`) shows the same impact tier in a file's finding list and in the rewrite workflow.

- Rules: No Auto Generated Boilerplate (`CORE:C:0030`) does not flag an instruction such as "Do not edit files under `gen/` by hand." It flags generated-file banners: "Do not edit this file", "Do not edit directly", a "DO NOT EDIT" line of its own or one followed by a dash or a colon ("DO NOT EDIT - changes will be overwritten"), "auto-generated", "generated by <tool>".
- Rules: the Import Depth Within Limit rule text states the 4-hop limit the Claude check enforces.

- Install: the CLI requires Typer 0.12.4 or newer; with Typer 0.12.0 to 0.12.3 installed, every command crashed at start.

- Levels and scorecard: Copilot, Cursor, Codex and Antigravity projects reach the capability level their own skills, agents, hooks and scoped instructions support, instead of stopping at L2 (L5 for Cursor). For Codex and Antigravity, per-folder instruction files count as scoped instructions. Skills and agents that live under a Claude plugin folder count toward the capability level, while plugin skills and agents inside an excluded folder no longer raise a project's capability level. The scorecard files Copilot's main file under Main, and Cursor and Copilot rule files under Rules. The per-surface health rows pair two surfaces per line only when both fit the terminal width. A project with no instruction files reads `Level: L0 System`. A whole-project run with no instructions to score, or no scorable content, reports "not scored" / `n/a (no scorable content)` in text and `null` in JSON instead of `0.0/10` or a failure.

- Privacy: the `description` text in a skill's, agent's or rule's frontmatter no longer leaves your machine (only a numeric summary of it is sent), and file paths are sent relative to the checked project — with none of the folder names between where you ran the command and the project — so your home directory and user name stay local. Findings, scores and the paid remedy's file locations are unchanged; a file's local and server findings stay together in the output, and a finding on a nested file that shares a root file's name (such as `tests/CLAUDE.md`) is no longer attributed to the root file.

- Agent detection: a Claude project with `.claude/rules/` plus skills or agents is checked with Claude's rules, including the hard-coded-credential check, instead of falling back to a generic rule set that reported nothing. A root `AGENTS.md` in a Codex, Cursor or Copilot project is attributed to that agent, so the scorecard names the right agent and topic-overlap findings fire, and When two agents each own files in one project, each agent's rules run on its own files. Checking a subfolder of a project anchored by `.ails/` or an agent folder keeps the project's own rules and skills in scope. `validate` in the MCP server reports the same findings as `ails check` on the same project.

- Model and sign-in: the model cache is repaired only when a model file is actually missing or damaged — any other load error is reported as it is, without a re-download — two checks repairing at once no longer delete each other's files, and with `AILS_MODEL_OFFLINE=1` a damaged file is reported and nothing is downloaded. A long-running MCP server repairs a model file that is damaged later in the session, and a repair that fails partway is retried instead of being taken as done. A model that fails to load for a reason other than damaged files is not verified again on every call in a long-running server, and a model download that failed is tried again a minute later instead of staying broken until restart. A model update always refreshes cached results. Writing a key into an existing `credentials.yml` makes it owner-only even when it was readable by others before, and the file is owner-only from the moment it is written. Signing in with a Pro key no longer shows an upgrade pitch.

- Messages: signing in on a free account says what the account enables instead of "Welcome to the beta! Full diagnostics unlocked.", and the free and anonymous summary offers what Pro adds (the remedies and the order to apply them) while a Pro run says where its fixes are. A project over the 500-file limit is told the limit is the same on every plan, with no upgrade offer. A rejected API key renders its own sign-in message instead of the bug-report link, `ails auth login` no longer persists or echoes a retired default tier, a missing tier is no longer shown as `free`, an unrecognised tier name no longer downgrades a paid session, and `team` sessions that hit an absolute cap get the contact form rather than the upgrade prompt. A server error message containing an unmatched closing tag no longer crashes the terminal output, and a rejection with an upgrade link no longer leaks terminal markup into machine-read output, the GitHub `::warning::` annotation or the MCP `funnel` object (which gained `status` and `tier`).

- Heal: a rewritten prohibition that now bans something the original never named, or stops banning something it did, is no longer reported as kept; the report names what was added or dropped. Naming what the original already referred to, or adding an example, is still accepted.

- Paid remedy: an instruction with two or more different weaknesses — vague and too brief, say — again carries a Compound Weakness (`CORE:C:0051`) finding in its location, telling your agent to fix them together in one rewrite; the rule had stopped firing. `validate` on a rewritten file no longer reports a polarity flip when a sentence that gives a directive and its negation together is only reworded, while a prohibition rewritten as a directive, a dropped negation, or a leading "never" turned into "always" still reports; adding or dropping a leading "always" alone does not. A constraint the rewrite left beside its directive is no longer reported as moved away when a similar instruction elsewhere in the file was reworded. A file's "too weak to be effective" finding is folded into its location's rewrite rather than repeated on its own, broad-scope wording is reported on your machine only (it no longer appears among the listed rules under the label `scope`), a rule with several checks gets the fix for the check that found the problem, every fix is served in full, and a row that points at a line carries the messages of the findings it fixes there.

- Check: a finding on a line that holds more than one instruction is graded on its own instruction, so a vague instruction sharing a line with a named one is no longer read as unlikely to raise the score or ordered late on Pro, and two too-brief instructions on one line no longer count one instruction's gain twice.

- Check: checks that expect a whole instruction file (a prohibition, a safety rule, headings, sections) run on each agent's main instruction file; a scoped rule, skill, agent, command or nested file no longer draws them. A Claude Code rule in `.claude/rules/` limited with `paths:` is treated as applying only to those files, as Claude Code applies it, and a topic-overlap finding between such a rule and `CLAUDE.md` says which file should keep the shared instructions. A `CLAUDE.md` or `AGENTS.md` in a subdirectory is analysed as loading only when work touches that subdirectory, and a subagent's memory file (`.claude/agent-memory/<agent>/MEMORY.md`) as loading into that subagent only; scores can change for projects with such files. Nested agent files (`.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, any instruction file in a subdirectory) are classified the same whether or not the background helper is running, including in MCP `validate` with no warm helper and on Windows.

- Check: a file in your home directory — your Claude auto-memory notes (`~/.claude/projects/*/memory/`), the user-scope `~/.claude/CLAUDE.md`, another agent's user-scope file such as `~/.codex/AGENTS.md` — takes the file type and loading its agent's config declares instead of reading as a generic file loaded every session, and the rules for that kind of file apply. A memory note other than `MEMORY.md` reads as recalled on demand, so two notes that never load together no longer report a topic-overlap finding. A file matching a later pattern of a file type is typed by it even when an earlier pattern of the same type matched first. A `.claude/CLAUDE.md` inside a subdirectory stays a nested instruction file; only the one at the project root is the main file. A file in a project without git, checked by its path, is no longer treated as part of your home directory when an editor folder such as `~/.vscode` exists there: it is checked in its own project, with that project's level and findings.

- Check: content-quality findings on memory files are suppressed — the auto-memory index (a list of `- [Title](file.md) — hook` pointers, not a human-written instruction file) and subagent memory (`agent-memory/` for user and project scope, `agent-memory-local/` for local scope, every memory folder the agent config declares) — in both `ails check` and MCP `validate`, for local and server findings alike, so the real memory-index findings are not drowned; a skill, agent or rule file under a `memory/` folder is still checked as one. A broken link in `MEMORY.md` reports under Markdown Link Targets Resolve (`CORE:S:0056`), and a memory note without its `name` / `description` / `type` frontmatter reports as `memory_frontmatter`.

- MCP: `remedy_brief` builds the brief once, so reading every part costs one analysis and a 650-line skill is now healable; it briefs a skill folder that nests sub-skills instead of refusing the whole location, briefs requested for many locations at once no longer fail on a project's first or any later run, and when a brief cannot be built the error says why. An unpaid caller is told the rewrite brief is a Pro feature instead of being sent back to `validate`. Single-file feedback leaves out findings the project workflow never counted. `preflight` rejects an unknown capability or agent and lists the known ones, every tool rejects unknown arguments, and the server reports its version.

- MCP `validate`: no longer starts an extra background process from inside the server, and a slow `validate` no longer stalls the server's other calls. An unrecognised configured agent reports the agent name and the known list instead of "no instruction files found", and a project with nothing to validate returns a clean empty result matching the terminal command. A single-file target is analysed within its real project and runs no whole-project checks, a server rate-limit or size-cap rejection is reported with its reason instead of looking like an outage, and files reached by an import are included as the terminal command includes them. After your coding agent edits an agent config file or the project config, or you sign in or change plan, the next `validate` reports the new state instead of repeating the earlier result and stopping the session. It also runs again after an edit to a skill's supporting file, or to any other file its last reply reported on, instead of repeating that reply.

- Output: `top_rules` entries carry separate `errors` and `warnings` counts, so a rule's total is no longer read as its worst severity. GitHub annotations for a file-level finding no longer carry `line=0`, and the `-f github` trailer reports `elapsed_ms`. JSON output carries `content_checks_skipped` when the content checks could not run. `ails explain` prints list values plainly. `ails daemon start|stop|status` no longer list an unused path argument, command help uses plain wording, and `ails explain --rules` help describes the option itself. `-f json` reports `content_checks_skipped: true` whenever a run could not read the instructions, not only when the model is missing. The "Top rules" summary names each rule by its title instead of a cut-off piece of one finding's message.

- Rules (Antigravity, Claude, Codex): Antigravity hooks are read from `.agents/hooks.json` with Antigravity's own event names and the global MCP config path is corrected; Claude and Codex hook event lists match the current vendor docs, Codex hooks written in `config.toml` are checked like those in `hooks.json`, and a hooks file with a valid event name next to a misspelled one is flagged. A Claude `@import` chain deeper than four hops is flagged, matching Claude's documented limit, and every Codex rule's source link resolves. A Starlark rules file (`.codex/rules/*.rules`) and a Codex agent definition are no longer checked by the rules written for markdown files.

- Rules (Codex): a Codex project with real settings in `.codex/config.toml` no longer draws empty-configuration, missing-permission and missing-restriction findings: a Codex config is judged by its own approval and sandbox settings (`CODEX:S:0006`, `CODEX:G:0001`, `CODEX:G:0002`), and a sandbox that is turned off is reported.

- Rules (Copilot, Cursor): the Copilot hooks rules follow GitHub's documented hooks format (camelCase event names, `bash`/`powershell` command fields, handler types), a `paths:` key in a `.claude/rules` file no longer draws a Copilot scoping finding, an `.instructions.md` file with `applyTo` loads on demand, and the setup-steps rule checks `.github/workflows/copilot-setup-steps.yml`. A correctly scoped Cursor `.mdc` rule no longer draws a scoping finding twice, Cursor skills under `.agents/skills` are found, a Cursor hook or command without the optional `type` is not flagged, and a Cursor `.mdc` rule's `globs:` are checked against the project's files.

- Rules: a valid `.claude/settings.json` no longer draws Hook Event Handlers, Settings Scope Declared or Hook Prompt Has Field findings that asked for markdown headings in JSON or for a prompt handler it does not use, and a real `permissions.deny` list satisfies Permission Config Denies Sensitive. MCP Config Declares Servers checks the file each agent reads MCP servers from (for Claude, `.mcp.json`) instead of `settings.json`, and Hook Event Handlers flags a hooks block whose handlers name no type without being fooled by a `type` key elsewhere in the file.

- Rules: a frontmatter or file-name rule reports every file that breaks it, not only the first, and one compliant file no longer hides a sibling that is missing its `applyTo` or has a bad name. `CLAUDE:S:0012` reports a `paths:` glob that matches no file on the rule file and line that hold it, naming the glob, instead of once on whichever rule file came first. Rules that check for a missing file name the file types correctly when a rule lists several (`config/hooks`) and look in the same folder on every run. A `checks.yml` that fails to parse is skipped with a warning naming the file, any other unexpected error surfaces instead of quietly dropping the rule's checks, an unreadable rule file is skipped with a warning naming it (`ails explain` then reports the rule as unknown), and a bundled agent definition that fails to load is logged as a warning naming the skipped agent.

- Rules (`CORE:S:0040`, `CORE:S:0057`, `CORE:S:0058`): frontmatter and manifests are read at their top level only — a key nested under another key, shown in a fenced body example or written after the closing `---` no longer satisfies the requirement, `author.name` no longer satisfies a plugin's `name` (including in a pretty-printed manifest), empty frontmatter is caught, and a CRLF file is read correctly. A `description:` written as a YAML continuation or block scalar is recognised, a UTF-8 byte-order mark no longer hides the frontmatter or manifest, and an unterminated frontmatter block no longer makes the check time out into a false finding.

- Rules: `skill-directory-kebab-case` (`CORE:S:0018`) no longer fires on a quoted kebab-case name (`name: "commit-helper"`), while an underscore or camelCase name still fires. `skill-name-matches-directory` (`CORE:S:0036`) compares the frontmatter `name` with the containing folder and flags a mismatch; a missing `name:` is not a violation (the folder name is used), and `ails explain` describes exactly that. Rule packs can use the `frontmatter_matches_dirname` check for any "frontmatter field equals folder name" rule.

- Rules: `permissions-ordered` (`CORE:G:0003`) no longer claims to verify deny-before-allow ordering, which it never did; it is retitled **Permission Config Declared** and checks that a config file declares a `permissions` block. Confirming that sensitive paths are denied stays the job of `CORE:G:0005`. `skill-description-length` (`CORE:S:0040`) is retitled **Skill Description Present** and checks that a `SKILL.md` declares a non-empty `description`, instead of claiming a character cap it never measured.

- Rules: `mermaid-diagrams` (`CORE:C:0039`) no longer flags every instruction file for lacking a diagram; it fires only where a branching procedure is present — a numbered list of three or more steps laced with conditional language ("if", "when", "otherwise") — and suggests a flowchart there. `directory-layout-documented` (`CORE:C:0035`) raises a single finding instead of two for a file missing a directory map, and an **Architecture** section satisfies it. `self-contained-skills` (`CORE:S:0017`) no longer says skill files "must include headings matching Input, Process, Output, and Constraints"; the check accepts any one of ten structural headings and the rule text says so, with two antipatterns corrected.

- `ails check`: the CLI no longer uses an `ails daemon` that runs a different installed version — such a daemon reads instruction files its own way, so a check could report the other version's results. A daemon left over from an older version is stopped and the next check starts this version's; a newer version's daemon is left running and the check analyses the files itself. `ails daemon status` names the daemon's `ails` version and whether this version uses it. A rare crash when two checks ran at the same time is fixed, and a fully cached run no longer loads the model when nothing needs it.

- Check: a scoped package name written inside inline code (`` `npx @scope/pkg check .` ``) is no longer mistaken for a broken import, and a file that imports another with `@path` is recognised as using imports. A file that only imports another file (a `CLAUDE.md` holding `@AGENTS.md`) no longer makes a later run report the imported file's findings on line 1: each file keeps its own line numbers from run to run.

- Check: content checks match each file's findings to that exact file; a file whose path was a suffix or part of another's could have the other file's findings reported against it. A pathological rule pattern can no longer hang a scan (every pattern search is time-limited and logged when it runs over); the 1 MB file-size limit is unchanged.

- Check (Docs and agents): the agent id `gemini` is `antigravity`; the agent ids are `antigravity`, `claude`, `codex`, `copilot` and `cursor`, and the `GEMINI.md` filename and `.gemini/` paths are still read as Antigravity's backward-compatible instruction surface. An Antigravity project's root `GEMINI.md` is scored under Main and a copy in a subfolder under Nested, as `CLAUDE.md` and `AGENTS.md` are; a project whose only instruction file was `GEMINI.md` showed no per-surface health at all. The published package keyword lists advertise `antigravity` instead of `gemini`, and the npm wrapper's `--help` matches the CLI's commands. The user-facing `docs/` match the shipped surface: the `--cwd` heal flag (opt into rewriting the whole project with `--heal`) is documented in Getting Started and the FAQ, the per-tier JSON field table is corrected (`fix` is not paid-only, `pro{}` is the upgrade hint on an unpaid run, `workflow{}` is the paid-only key), and a GitHub Action input/output reference plus the always-present JSON keys are documented.

- Paid remedy: when a finding you silence with `ails-disable-line`, or a finding in an agent's memory file that the check leaves out, takes a whole location with it, the workflow follows: its one-line summary counts the locations that remain, and `workflow.listed` no longer lists a rule whose findings were all removed.

- Docs: the agent support page says how a Codex user raises Codex's MCP startup and tool timeouts for a large project.
- Docs: the Pro plan's hourly limit is stated as 1,200 requests, and the privacy answers point to the privacy notice and say which words of your text are sent (a few instruction words from a short fixed list, such as `never` or `must`).
- Docs: the configuration page says that a list setting given in both your user and your project config combines both, while a single-value setting takes the project value; the capability-level page says a lone skill with no `CLAUDE.md` reads L0 under a plain `ails check .` ("No instruction files found.") and L1 under `ails check . --agent claude`.
- Check: folders listed in `exclude_dirs` in `.ails/config.local.yml` or your user config are skipped while files are found, not only when results are reported.
- Check: a `.vscode/settings.json` holding only editor settings is no longer checked with the agent permission rules. Cursor's agent settings are read from `.cursor/cli.json` (and `~/.cursor/cli-config.json` for your user), Copilot's `.vscode/settings.json` is no longer asked for a `permissions` list Copilot does not have, and a settings file whose keys contain dots (`"editor.formatOnSave"`) is no longer called empty.
- Check: links and `@path` imports written inside code (fenced blocks with longer or tilde fences, fences inside list items, indented code blocks, double-backtick spans, a table cell's code span holding an escaped pipe), including in a memory index, are no longer reported as broken links or unresolved imports, and a link whose text is code (`` [`name`](file.md) ``) is now checked by the broken-link rule. A link to a file whose name has spaces or non-ASCII letters resolves, and such files are found when following links.
- Check: a memory note whose frontmatter is not valid YAML is reported as a finding on the index line that links it.
- Check: a `.ails/config.yml`, your user config or a `.ails/backbone.yml` that cannot be read (not valid YAML, or not UTF-8) is reported once per run, on one line naming the file and the line of the problem, instead of being passed over or repeated.
- Check: a rule file whose frontmatter is not valid YAML fails its frontmatter checks with the YAML problem and its line, instead of printing an error trace.
- Check: a Cursor rule with an unquoted `globs: *.tsx` keeps its scope.
- Check: a code span written with a double backtick, an escaped backtick or an empty backtick pair is read the way markdown reads it when naming code and splitting instructions.
- Paid remedy: the rewrite brief's line fixes read code the way markdown does (a double-backtick span, an escaped or unmatched backtick), so a fix is not proposed for text that is already code.
- Rewrite check: a rewrite that drops one of an instruction's conditions ("If the build fails, run `make clean` before running `make build` again." to "Run `make clean` before running `make build` again."), drops one of two conditions joined by "and" or "or", or changes a condition ("if the build fails" to "if the build passes") is reported as a dropped condition; a condition restated with another marker, another form of its words ("before committing" to "before you commit") or a pronoun still passes.
- Sign-in and limits: after upgrading to Pro, the next check uses the Pro limit straight away instead of repeating the free-limit message for up to an hour.
- Agent session: heal sees a Pro upgrade on its next run instead of repeating that Pro is needed.
- First run: the model download is given as about 275 MB, its real size, in the download message, the README and the docs.
- Check: `ails check --help` says `--strict` exits 1 on any reported finding, info level included.
- Check: a run refused by the service, such as one over the hourly limit, names your plan and says why it has no score instead of reporting the service as offline.
- Sign-in: when the website refuses `ails auth login`, the CLI says why and what to do, and when the website does not answer it says to try again, instead of a raw HTTP error or a traceback. When GitHub sign-in cannot create an account because the email is already in use, `ails auth login` points you to reporails.com/contact.
- Sign-in: `ails auth status` shows the plan your last check saw, so a new Pro subscription (or a cancellation) shows there after your next check, rather than the plan you had when you signed in.
- Check: a project whose only instructions are Antigravity rules in `.agents/rules/` is found and checked, with or without `--agent`.
- Check: a whole-project run set to one agent (with `--agent` or `default_agent`) that finds none of that agent's files now names the other agents the project has files for and how to check them, instead of asking for that agent's file; a check of an empty folder keeps its usual message.
- Windows: files are classified, matched and reported with the same forward-slash paths as on macOS and Linux, so Cursor, Copilot, Antigravity and Codex files, skills and home-folder instructions are recognised there.
- `ails rules` and `ails explain` no longer describe the one-instruction-per-sentence and broad-conditional-scope rules as needing a server connection; both run on your machine.
- Python 3.13: a symlink loop in a project is skipped instead of being treated as a normal file or followed, on macOS, Linux and Windows.
- Check: the summary names the agent you passed with `--agent`, or the one it detected, also when the analysis model is not on disk.
- GitHub Action: the `min-score` gate fails when content checks were skipped, instead of passing on a partial score.
- MCP: a `validate` call that hit a busy or slow server can be retried on the same file instead of being refused as a repeat; the reply says it is retryable and how long to wait, and retries still count toward the per-file call limit.
- Heal: settings, hook and MCP config files are no longer rewritten. Their findings stay in the check output with their impact grade, and are listed for you to edit by hand.
- Check: the topic-overlap summary says "+1 more pair" instead of "+1 more pairs".

### Removed

- Check: the per-file "Capacity saturation across N topics" finding (`CORE:C:0044`) and the "Skill/agent descriptions in base context compete with this file's topics" warning are gone, together with the workflow's "split each listed file into one file per topic" step and the "descriptions compete for attention" note; the topic-overlap check above replaces them.

- Check: the client-side topic grouping is removed, and with it the `ails heal` fix that moved constraints ahead of directives within a topic and the local ordering / orphan check. `ails check` scores are unchanged, and instruction-ordering and orphaned-constraint findings still surface.

- Check: the older way of reading instruction direction is removed and its model files are no longer downloaded; a project that selected it uses the current model, and `ails check` output shape is unchanged. The model files it replaced are no longer shipped (~88 MB).

- Check: the cross-file "conflict" diagnosis no longer surfaces — `ails check` and the scorecard no longer show a "conflicts" count or the error-severity icon, and `stats.cross_file_conflicts` is gone from `-f json`; the `repetition` finding still surfaces.

- Rules: the bundled rule files no longer carry `fix:` remediation text or a `## Fix` section. Fix guidance is delivered per finding by the diagnostic service (tier-gated); rule detection, severity, categories and every other field are unchanged.
- Check: the summary's closing line "An error is worth fixing even when clearing it barely moves the score." is gone.

### Internal

- Checks, heal and the MCP tools read code spans, fences, links, emphasis and frontmatter the same way, so they agree on what a file says: a heading-looking line inside a fenced example on a rule page no longer ends its section, and an unreadable `checks.yml` is logged. Results on other files are unchanged; the local cache is rebuilt once.
- Names are imported from the module that defines them; the compatibility re-exports and wrappers are removed.
- The analysis data format was updated; it still never includes the text of your instructions, and results are unchanged.

- The test suite no longer sends the checks it runs to the hosted diagnostics service, and passes in development mode. This now also holds for the end-to-end smoke tests.
- The pre-release check stays on the machine when no server address is given, and a release workflow step no longer runs a command that appears inside its test fixture.
- The unit and integration test suites skip the tests that need the model files on a machine that has none, instead of failing.
- Comments, docstrings and class names in the source, and the messages of the release workflow and the pre-release check, say what the code does in plain words.
- Test names, docstrings and sample inputs in the test suite say what is tested in plain words.
- `ails test` passes on a fresh clone: the source files three path-scope rule fixtures need are tracked.
- The unit suite ends without failures on a machine with no model files: the tests that need no model run without it.
- The tests that need the model files pass where the models are installed: the two-agent check test and the heal smoke fixture follow the current behaviour.
- The test suites pass on a machine without the model files and skip exactly the tests that need it, as on CI, give the same results on a CI runner as locally (they no longer inherit the runner's CI variables, which switch the default output to JSON), and collect and run on Windows (tests that need POSIX-only behaviour — file modes, interval timers, case-sensitive file names, symlinks, bash, the daemon socket — skip there, and tests no longer depend on the platform's default encoding or the HOME variable); the source type-checks for Windows again, and the GitHub Action's self-test no longer expects a min-score gate to pass without a server.
- CI and the release gate run the QA suite on Python 3.12 and 3.13 as well as on Windows; `typer` is capped below 0.22; an always-empty field is no longer uploaded and unused helpers are removed; Windows test expectations use the forward-slash paths the CLI reports.
- The source archive carries tracked source only: no cache, project-settings or scratch folders. The GitHub Action's `version` input says what an empty value installs, and the Action's own test asserts that a minimum-score gate fails when the diagnostics service is unreachable.

- Code structure, module layout, docstrings and comments tidied and unused code removed; tests, test tooling, build, CI and release checks expanded and tightened; maintainer tooling for development checkouts; the published package and source archive no longer include build-machine leftovers, local-only test data or maintainer scripts. No change in behavior or output. Comments and docstrings in the source, the tests, the workflows and the scripts describe what the code does.
- The release branch and the release pull request run the release's full QA and wheel checks, on Windows too, before the merge publishes anything, including the PyPI upload's own metadata check; the PyPI upload reads the package's current metadata format.

## 0.5.12

### Added

- check: inline per-line finding suppression. Mark a single reviewed line with `<!-- ails-disable-line CORE:C:0047 -->` to silence just that one rule on just that line, while the rule keeps firing everywhere else. The directive is an invisible HTML comment, must name the rule (space/comma-separate several), and never changes how the rest of the line is analyzed. See `docs/configuration.md`.
- testing: added internal regression coverage to keep `ails check` output stable across refactors.
- testing: added an architecture check that keeps error handling at the network boundary consistent, so faults surface clearly instead of being silently swallowed.
- testing: opt-in live-network lane exercising the `ails auth login` activation path so first-contact auth regressions surface in CI rather than at a new user.
- testing: the suite now runs against an isolated home directory, so a contributor's machine-wide config (`~/.reporails/config.yml`, `~/.codex/`, `~/.claude/`) no longer leaks into agent-detection tests — they pass or fail the same way locally as in CI. Includes a regression test pinning that a global `~/.codex/config.toml` cannot hijack detection of an `AGENTS.md`-only project.
- testing: the end-to-end smoke suite now runs in CI on every push. It is hermetic — diagnostics run offline (no network), home is isolated, and the few assertions that can only be observed through the bundled mapper model skip cleanly on the model-free runner — so smoke regressions are caught in CI instead of shipping green.
- testing: the rule-library lint pass (`ails test --lint`) now runs as part of the QA gate, so a duplicate rule ID anywhere in the rule library or a malformed rule fails the gate instead of slipping through unnoticed.
- testing: new CI-gated coverage for three previously-untested behaviors — `ails check --heal --dry-run` leaving files unmodified, the friendly "Path not found" error on a bare keyword that is neither a path nor a capability, and multi-target `ails check` (several targets in one invocation) scoping the scan to exactly those targets.
- testing: hardened that new coverage — the multi-target test now asserts against a file the scan would otherwise discover, so it genuinely proves out-of-target scoping, and the `--heal --dry-run` no-mutation test documents that its full assertion runs only where the bundled model is present.

### Changed

- rules: renamed the Google agent rule pack and registry entry from `gemini` to `antigravity`, following Google's 2026-06-18 retirement of the Gemini CLI in favor of the Antigravity CLI. The pack still validates legacy `GEMINI.md` / `~/.gemini/` files for backward-compat and now also recognizes Antigravity's `AGENTS.md` primary and `.agents/` skills layout. `ails check` reports the agent as `antigravity`; the five implemented agents are now claude, codex, copilot, cursor, antigravity.
- testing: normalized code formatting in two test modules (no behavior change).
- check: `ails check --heal` now requires you to name what to fix. A whole-project heal — a bare `--heal`, or `ails check . --heal` / `ails check ./ --heal` — is refused; pass an explicit target (`ails check CLAUDE.md --heal`), preview everything with `--dry-run`, or opt into a whole-project rewrite with the new `--cwd` flag. `--heal` also never writes through an in-tree symlink whose real file lies outside the named target, so a scoped heal cannot modify files outside its scope. Prevents accidental project-wide and out-of-scope rewrites.
- check: applying fixes now requires an account. The diagnosis stays free for everyone, but `--heal` (apply or `--dry-run` preview) needs sign-in — anonymous users get the full diagnosis plus a prompt to run `ails auth login`. This keeps the free experience honest: the diagnosis names what to fix; the fix is the account feature.
- explain: `ails explain <rule>` now shows the rule's Pass / Fail examples, matching `ails rules -f md`. Both surfaces draw examples from the same fence-aware extractor, and both now name an absent example block ("no Pass / Fail examples") instead of silently omitting it.
- json: `-f json` and the `--format github` trailing JSON now emit canonical rule IDs (e.g. `CORE:S:0039`) for findings that previously carried a bare client-side token like `format` or `orphan`, matching the text output. The raw token is preserved under a new `label` key when it differs, so machine baselines keyed on it stay stable. As a result those findings now carry a populated `category` and join the per-surface category breakdown, and `top_rules` is keyed by canonical ID. (The `ambiguous_charge` classifier-confidence marker has no canonical rule and intentionally stays label-only.)
- rules: a rule's check can now declare `project_scope: true` in `checks.yml` to be skipped on a narrowed (single-target) run where a whole-project aggregate is meaningless — previously this was hard-coded in the engine, so adding such a rule required a code change. No change to default whole-project scans.
- help: the `npx @reporails/cli` help output now lists the `ails rules` command.
- check: the collapsed lower-priority findings row no longer claims those findings "won't move your score yet" — it now reads `+N lower-priority · -v to list`. The old wording implied the deferred findings would move the score once the higher-priority ones were fixed, which overpromised; the row simply marks the collapsed tail.

### Fixed

- check: a neutral sentence is no longer flagged as ambiguous when the only instruction-like word sits inside a Markdown link label, a citation reference, or a `code span` — those are references, not instructions. Genuine inline instruction language in a neutral sentence still surfaces. Reduces false positives on documentation prose that links to or cites a rule by name.
- auth: clearer errors when the credentials or config file can't be read — a corrupt file now produces a visible warning and the session continues with anonymous access, instead of a silent tier downgrade.
- performance: `ails check` is substantially faster on large projects, with identical output.
- auth: `ails auth login` now gives a clear, actionable error when the auth endpoint is reachable but returns an unexpected response (a non-200 status or a non-JSON body) — "retry shortly or contact support" — instead of a generic HTTP error or a misleading "OAuth not configured" message. Both the client-id lookup and the token-exchange step surface it.
- check: a whole-project scan no longer lets your machine-wide agent config decide which agent a repository is. A global home-directory file such as `~/.codex/config.toml` could make `ails check` treat a project that only has an `AGENTS.md` as that specific agent's project, narrowing the findings to that agent's rules instead of the cross-agent core set. Discovery now ignores home-scope (`~/...`) paths during a repository scan; those surfaces remain reachable only when you target them explicitly (e.g. `ails check subagent_memory`).
- check: a whole-project scan again surfaces the project's own auto-memory (the Memory segment). A recent change that stopped a machine-wide config from deciding a repo's agent had also dropped the project's per-project memory, which is keyed to this project specifically and is not a cross-project surface — it now shows again, while another project's memory still stays out of scope.
- check: the bridging caption "the listed errors are still your worklist" no longer appears when there is no error list below it. Anonymous and free-tier runs that show a quality score but gate the per-finding list behind sign-in previously printed the caption pointing at a list that wasn't there; it now appears only when error findings are actually listed.
- check: per-surface health bars stay column-aligned when a surface name is long and its file count reaches two digits — the name column now sizes to the widest label in the set instead of a fixed width.
- check: targeting a directory (`ails check <dir>`) no longer drops instruction files that are symlinks pointing outside that directory; an in-tree symlinked file under the target is now scanned.
- update: rule-framework archive extraction is forward-compatible with Python 3.14's stricter tar handling (uses the safe `data` extraction filter).
- check: `--heal` now leaves a line you marked with `<!-- ails-disable-line ... -->` untouched — a line you reviewed and silenced is no longer auto-rewritten. `--heal` also never writes through a symlinked file (including a capability target like a `.claude/rules/` symlink) whose real path lies outside the named scope, and skips a file whose `@import` directives would shift its line numbers rather than risk editing the wrong line.
- check: inline `ails-disable-line` suppression directives are now honored on the MCP `validate` tool too, matching `ails check` — an agent no longer re-flags a finding you already dismissed.
- check: `--exclude-files` (and `exclude_files` config) now also excludes a file reached only via an `@import` from a non-excluded file; previously such a file silently re-entered the scan. Naming an excluded file explicitly (`ails check VENDORED.md`) still scans it — an explicit target overrides the exclusion.
- check: `ails check <file> --heal -f json` run anonymously now still emits the full diagnosis JSON (the auth notice goes to stderr) — a machine consumer that adds `--heal` no longer loses all diagnostic data.
- check: `--strict` now exits non-zero for a displayed error on a user-scope target (e.g. `ails check subagent_memory --strict`), matching what the run displayed.
- auth: a session no longer silently downgrades to the free tier when the server returns a tier alongside an otherwise-unparseable response body.
- testing: the heal scope-safety regression for `ails check . <token> --heal` now runs in an isolated working directory, so it no longer depends on the checkout carrying a root `CLAUDE.md` — it passes identically in CI and locally.
- testing: the uppercase-agent smoke test now requests text output explicitly, so it asserts the human "No instruction files found" message reliably under CI (where the default output format is machine-readable) instead of only locally.
- testing: the project auto-memory regression tests skip on Windows, where the `~/.claude/projects/<slug>/memory/` slug derivation is POSIX-path-shaped and does not form a valid Windows path component — the behavior they assert holds only on POSIX.

### Removed

- internal: removed two unused output-rendering helpers; no change to `ails check` output.
- internal: pruned several unused internal modules (a feature-summary helper, a display stub, a dead init path, a rules-path resolver, and an orphan-feature detector); no user-facing behavior change.

## 0.5.11

### Added

- rules: `ails rules` — new subcommand exposing the framework rule registry as a queryable surface. `ails rules list` enumerates rules with repeatable `--capability` filtering (sorted by category: structure → direction → coherence → efficiency → maintenance → governance; severity as tiebreaker), plus `--agent` and `--severity` filters and three output formats: `text` (compact), `md` (rich, Pass / Fail blocks by default; `--no-examples` opt-out for shorter context payload), `json` (structured). `ails rules agents` enumerates known agents; `ails rules capabilities` enumerates the capability vocabulary for an agent. Rule-detail browsing stays on the top-level `ails explain <id-or-slug>` (accepts either a rule ID like `CORE:S:0024` or a slug like `section-headers-present`). The markdown form pipes directly into an AI authoring agent's prompt so it writes rule-compliant content from the start rather than patching findings after `ails check`.
- check: `ails check` now takes variadic typed targets: each positional is `capability:name` (`skill:backlog`), a bare capability noun (`skills` for every skill), or a path (`./CLAUDE.md`). Mixable; no targets = whole-project scan. A leading Windows drive letter (`C:\...`) is treated as a path, not a `capability:name`. The previous two-positional polymorphic shape is gone. Replaces `ails check skill backlog` with `ails check skill:backlog`.
- cli: root-level `--version` / `-V` flag prints the version string (subcommand `ails version` still prints the full install-method readout). `-h` accepted everywhere as a `--help` alias. Shell completion callbacks wired to `ails check <target>`, `--agent`, and `ails explain <id-or-slug>` — install via `ails --install-completion` to enable.
- check: `--fix` added as an alias for `--heal` (`ails check --fix`), matching the `eslint`/`ruff` convention; `--heal` stays primary, both show in `--help`.
- cli: `ails --help` groups commands into four intent panels — Get started (`check`), Explore (`explain`, `rules`), Account & setup (`auth`, `config`), Maintenance (`install`, `update`, `version`). Command summary lines are normalized to one imperative clause each. `ails check --help` describes the target forms on the `targets` argument and points to `ails rules capabilities`.
- rules: `ails rules capabilities` now shows, per capability, the path glob it resolves to and how many targets are found in the current project (previously listed names only). JSON gains a `resolution` array alongside the existing `capabilities` name list.
- check: `ails check @referenced` — new capability listing surface for `[text](path)`-reached markdown files (`file_type: referenced`). Virtual-capability path: agent-agnostic (markdown links are universal), enumerates classifier output rather than agent-config globs. Requires `.ails/config.yml: generic_scanning: true` to populate; otherwise empty.
- check/json: `-f json` gains two additive keys — a per-file `regime` object (`named`, `within_capacity`, `confidence`) describing how much room a file has to improve, and a per-finding `leverage` tier (`gate_mover` / `conditional` / `cosmetic`) ranking how much each finding is likely to move the score. The raw `severity`, `score`, and `violations` fields are unchanged, so existing consumers and CI baselines keep working.
- rules: new `scheduled_tasks` capability in the agent capability matrix — recognizes scheduled-task / automation surfaces (cron / scheduled-run / automations) where an agent exposes them on disk. Surfaces in `ails rules capabilities`; the matrix now carries 16 capabilities.
- check: `exclude_files` config key (and `--exclude-files` flag) excludes individual files from a scan, complementing `exclude_dirs`. Each entry is a glob matched against the file path relative to the project root (`pathlib` semantics: each `*`/`**` segment matches exactly one path component — not a recursive globstar — so a pattern matches at a fixed depth), so you can name an exact file (`.claude/agents/lead.md`), files one level down (`.claude/skills/*/SKILL.md`), or any file by basename (`**/lead.md`). Anchor patterns to a path prefix — a bare `**` matches every file and drops all instruction files. The motivating case is a project that symlinks coding-agent harness files in from elsewhere — they are owned and linted where they live, so listing their paths drops them from scoring noise here. Accepted in both project and global config; explicitly targeting an excluded file (`ails check ./.claude/agents/lead.md`) still scans it, since exclusion applies to discovery only.

### Changed

- check: a file with no scorable instruction content now renders as `not scored` instead of a misleading full score. This covers a non-instruction surface a coding agent still reads (e.g. a `.cursorignore` path list, which carries no instruction quality to measure) and an empty instruction file. Such files show no score and no health bar, and are excluded from the per-surface and whole-project roll-up, so they neither read as top-quality nor drag the headline. In `-f json`, an all-unscored surface's `surface_health[].score` is `null`; surfaces with any scored file keep a numeric score.
- check: with `generic_scanning: true`, files reached by an `@`-import (which the harness eagerly auto-loads) are now mapped + scored and surface as an `Imported` bar that counts toward the whole-project Quality — closing a gap where eagerly-loaded context was silently omitted from the score. Files reached only by a `[text](path)` markdown link (discoverable, not loaded unless read) get their own labeled `Referenced` file-panel group (findings only) and are deliberately kept out of the score and the headline, since scoring a file the agent never loads would be a false signal. A one-line note names the headline shift on runs that have Imported files. No effect when `generic_scanning` is off.
- check/json: `-f json` (and the trailing JSON line of `--format github`) now carries top-level `quality` (the whole-project Quality score, `null` when offline) and `level` (the maturity level, e.g. `L4`), matching the text headline. Previously the combined-result JSON exposed only per-surface `surface_health[].score` with no whole-project verdict, so a JSON consumer (the GitHub Action, the plugin) could not read the headline number and had to re-derive one. Additive keys; existing fields unchanged.
- ci/action: the `reporails/cli/action` `score` output and the `min-score` gate now read the real `quality` verdict from the check JSON instead of recomputing a severity-tally approximation (the pre-single-score model). `level` is read from the JSON `level` key rather than hardcoded. An offline run (no server score) leaves `score` empty and the `min-score` gate logs a warning and skips instead of failing on a fabricated number.
- check/json: `-f json` `surface_health` now routes `@`-import (`generic`) files to the `Imported` surface when `generic_scanning` is on, matching the text scorecard. Previously the JSON surface partition disagreed with the text view for the same run (`file_type_by_path` was threaded only into the text formatter).
- mcp: `validate(path)` now keys per-file `regime` and per-surface health against the validated path instead of the server's working directory. When the validated path differed from the MCP server's cwd, the regime block silently dropped and surface scores misrouted; the JSON consumer (the plugin) got degraded data with no error. Threaded `project_root` through `format_combined_result` into `compute_surface_scores`.
- check: every rule ID in the text output is now a clickable link to its documentation page at `https://reporails.com/rules/<agent|core>/<slug>` (e.g. `CORE:E:0003` → `/rules/core/formatting-regime`). Terminals that support hyperlinks make the ID clickable; others show the plain ID unchanged.
- check: the `Findings` line no longer appends a `score-movers` count. The count mixed the leverage axis (how much a fix moves the score) with the severity histogram (errors/warnings/info) on one line, which read as inconsistent — e.g. 96 errors but 42 score-movers, because most structural and mechanical errors are not score-movers. The leverage signal still drives the inline triage: gate-mover findings stay as listed lines and the rest collapse into `+N lower-priority (won't move your score yet)`.
- check: client-side findings now display their canonical rule ID in the text output, matching server findings — a backtick-formatting finding reads `CORE:E:0003` instead of the bare label `format`, charge-ordering reads `CORE:D:0003` (was `ordering`), broad conditional scope `CORE:C:0048` (`scope`), an instruction-in-heading `CORE:S:0039` (`heading_instruction`), and a prohibition with no paired directive `CORE:C:0053` (`orphan`, the degenerate weak-instruction case). The Top-rules block now merges client and server findings that share a rule ID into one row. Only the displayed token changed; `-f json` keeps the raw labels for baseline stability.
- check: offline runs (server diagnostics unavailable) no longer render every surface as `not scored`. The per-surface and per-item score bars are suppressed when there is no server analysis at all, leaving the `Quality n/a` headline, the findings, and the scope summary — only genuinely scored runs show the bars. Online behavior is unchanged.
- check: the structural-completeness signal (missing required sections, presence and hygiene gaps, an over-limit instruction chain) now resolves an agent's own structural rules, not just the generic core set. An agent rule that supersedes a core structural rule — e.g. Codex's hard 32 KiB `AGENTS.md` cap (`CODEX:E:0001`) superseding the generic size rule — was being dropped from the signal, so an over-limit Codex chain did not actually lower the score. It now does: the over-limit chain is folded into the delivery factor so the score reflects the silently-truncated content.
- Internals: the SIGALRM wall-clock backstop guards (`interfaces/cli/main.py`, `core/mapper/daemon.py`) now branch on `sys.platform` instead of `hasattr(signal, "SIGALRM")`. `mypy` narrows a `sys.platform` check but not a `hasattr` guard, so the `--platform=win32` cross-check flagged `signal.setitimer`/`signal.ITIMER_REAL` as missing attributes and the pre-release gate failed. No behavior change (both forms no-op on Windows); host + win32 `mypy` now clean.
- Internals: `interfaces/cli/main.py` variadic-target classification narrows the `_classify_target_token` payload with `isinstance` instead of suppressing the union with `# type: ignore`. No behavior change; clears three latent `mypy` errors (`unused-ignore`, `union-attr`, `arg-type`) so the type gate is green.
- Internals: New `core/platform/adapters/rules_query.py` adapter (load + filter + sort + fence-aware Pass/Fail extraction) backs the `ails rules` verb. CLI surface lives at `interfaces/cli/rules_command.py` (Typer sub-app) calling shared `list_checks` in `interfaces/cli/checks_command.py`. 18 unit tests + 7 integration tests cover loader / filter / sort / command / examples.
- Internals: `tests/unit/test_rule_id_uniqueness.py` collapses the duplicate-id comprehension onto one line to satisfy the line-length linter. No behavior change.
- Internals: `test_single_file_scan_matches_whole_project` marked `xfail` — it compares a cwd-nested single-file scan against a dir-target that reroots at the subdir; under the cwd-is-project-root principle the rerooting is the deviation, tracked for a post-release decision.
- Internals: review follow-ups — deduped `_is_external_pattern` (one canonical copy in `agent_discovery`, imported by `capability_paths`, was divergent); `per_file_stats` now requires `project_root` to match its sibling `get_group_atoms` (no silent `Path.cwd()` fallback); added an e2e guarding that `ails check subagent_memory` reaches global `~/.claude/agent-memory/` files.
- Internals: tightened inline comments in the mapper classifier and embedder to describe behavior; removed two stale code-reference comments in `core/classify` and `core/platform/dto`. No behavior change.
- Internals: integration tests made CI-robust — `test_score_displayed` asserts the always-present `Quality` headline (a score online, `Quality n/a` offline) instead of a score value, and the `ails rules` help assertions strip ANSI and force a wide, color-free render so option tokens (`--capability`) are not split by escape codes on CI runners.
- Internals: `test_check_single_file` made Windows-robust — the single-file findings test runs from the project directory with a relative target so path normalization stays single-drive (Windows pytest `tmp_path` and the repo checkout can land on different drives, breaking the display filter's `relative_to`), and the subagent-memory test sets `USERPROFILE` alongside `HOME` so `Path.home()` resolves the fake home on Windows.
- Internals: `test_checks_command._run` decodes subprocess output as UTF-8 to match the CLI's UTF-8 stdout; under the OS locale (cp1252 on Windows) the reader thread died decoding the rich help panel's box-drawing glyphs and `proc.stdout` came back `None`.
- Internals: `test_capability_paths` normalizes relative paths via `as_posix()` so the nested-`CLAUDE.md` enumeration assertions pass on Windows, where `str(Path.relative_to(...))` yields backslash separators that broke the forward-slash comparison.
- mcp/json: validate response now carries `tier` at top-level, `category` per finding (derived from rule id via the existing `Category` enum), and `category_breakdown` per surface in `surface_health`. Consumers can render tier-aware presentation, group findings by category, and triage by prioritizing surfaces with the heaviest category buckets.
- mcp: trimmed tool surface to `validate`, `preflight`, `explain`. `score` and `heal` removed — score is derivable from the validate response's stats + surface_health; heal is replaced by the slash command body's fix-walk loop (model uses `Edit` per finding with the response's per-finding `fix` text). New `preflight(capability, agent?)` returns workflow-ordered rules with Pass / Fail example blocks for the author-it-right-first loop. `validate` accepts file-path targets (previously rejected with `not_a_directory`) and now returns a structured `needs_install` payload when the framework is missing (previously a bare error). CLI `ails check --heal` continues to serve batch deterministic use.
- rules: per-rule `fix:` text now lives in `rule.md` frontmatter — canonical operator-facing fix text consumed by `LocalFinding.fix` at emission time. 26 rules received canonical fix text; framework-wide fix coverage in validate responses moved from 96.3% → 100% on the cli's own corpus. Cap: 1000 chars per rule, mirrors the skill-description ceiling. Authored once in `rule.md`, surfaced everywhere — the plugin reads `finding.fix` to drive an Edit-per-finding loop.
- classify: Link-reached files split into two file types — `[text](path)` markdown-link reach classifies the target as `file_type: referenced` with `loading: discoverable`; `@<path>` import reach keeps `file_type: generic` with `loading: session_start`/`on_demand` per source eagerness. Mixed reach (both `@` and link from any source) routes to `generic` — the import path's auto-load guarantee dominates the link-only path's discoverability. Matches the actual harness loading model: only `@`-imported content enters context budget without an explicit `Read`.
- Internals: New `tests/skills/<skill>/` subtree for subagent-driven manual validation procedures (not `pytest`). Initial: `/ails` skill procedure + deliberately-imperfect fixture exercising check / explain / heal / preflight / fallback cases.
- check: `ails check` now leads each file panel with its highest-leverage findings and collapses the low-priority remainder into a single `◦ +N lower-priority (won't move your score yet) · -v to list` row, so the report surfaces what actually moves your score instead of a flat wall of findings. Repeated same-rule findings fold into one `(×N)` line. `-v` restores the full per-line view, and severity is re-keyed by leverage rather than raw symptom count. The collapse is driven by a per-file read of the server's analysis; files where that read is uncertain keep the full findings view. The boxed panels, summary scorecard, `Level:`, `Top rules`, and footer are unchanged.
- check: `ails heal` folded into `ails check --heal`. The standalone `heal` verb is removed; healing runs as a flag on `check`, reusing the already-built ruleset map and discovery (no double-mapping). `--dry-run` previews fixes without writing. Output: text mode shows the standard scorecard followed by the heal summary; JSON mode emits the heal payload (single document, parseable). The validate-then-fix workflow becomes one verb instead of two.
- check: the summary now leads with a single **Quality** score (0-10) — the analysis service's own verdict on how well-formed your instructions are, shown verbatim (the CLI holds no scoring constants). The score discriminates: a problem-heavy file scores well below a clean one, where the previous score read near the top for almost any file regardless of its findings. Structural completeness (missing required sections, presence and hygiene gaps) and any content silently dropped past an agent's hard instruction-size cap are folded into the score as a delivery factor, so a file that loses instruction content can no longer read as high quality. Findings stay a separate worklist (errors / warnings / score-movers) beneath the score; a high score above open errors shows a one-line caption naming the split. The whole-project and per-surface numbers are the atom-weighted roll-up of the per-file scores, so the headline never contradicts the per-surface / per-file bars, and each per-surface bar carries its own error count (`Rules 8.0 · 1 err`). `-f json` keeps the same `surface_health[].score` key and shape; `severity` and `violations` are untouched.
- check: each finding's priority tier (`gate_mover` / `conditional` / `cosmetic`) is now computed by the server's analysis for that finding *in the context of its own file*, replacing the previous fixed rule-to-tier lookup. The same rule can rank as high-priority in one file and low-priority in another depending on how much room that file has to improve — so the `◦ +N lower-priority` collapse and the `-f json` `leverage` key reflect what actually moves each file's score rather than a one-size-fits-all guess. The CLI falls back to the built-in ranking when run offline. The JSON shape is unchanged (same `leverage` key and values); `severity`, `score`, and `violations` are untouched.
- check: each surfaced finding now shows its remediation as a `→` action line beneath it — the per-finding fix text, written for that specific instruction rather than a generic rule blurb — so the report says what to do, not just what is wrong. Rendered in both the triaged and neutral views; the collapsed low-priority tail stays a single line.
- check: instruction-length findings recalibrated toward an 8-10 word range (optimum 9) — "too brief" now flags instructions of 6 words or fewer (previously 8), and a new "too long" finding flags instructions over 11 words. Both surface under the existing instruction-elaboration rule.
- rules: refreshed the bundled agent capability matrix and the five implemented agents' configs (claude, codex, copilot, cursor, gemini) against current official docs — added `memory` to codex, `output` to gemini, and `scheduled_tasks` to claude/codex/cursor; refreshed per-agent surface notes (hook-event counts, Cursor Memories, Codex memories). `ails check` discovery and capability-target resolution pick up the updated surfaces.
- Internals: new `scripts/validate_registry.py` enforces the matrix connection rule — every capability in an implemented agent's matrix row must resolve to a config `file_types` entry/scope or a documented unmeasurable-surface exemption; runs in CI as a registry guard.
- rules: corrected the guidance in four core rules (`instruction-elaboration`, `specificity-shields`, `formatting-regime`, `compound-weakness`) to be direction-aware. Positive directives should name the specific construct (tool, file, command); prohibitions should state the forbidden thing as an abstract category rather than naming or backticking it, because naming a prohibited construct can anchor the forbidden concept instead of suppressing it. Updated the Pass examples and fix text only — no rule IDs, categories, severities, or checks changed.
- check: `CORE:E:0001` (total instruction size) now measures the always-injected "one round" footprint instead of summing every instruction file on disk. Eager files (`loading: session_start` — `CLAUDE.md`/`AGENTS.md`/`GEMINI.md` + imports, the `MEMORY.md` index) count in full; progressive-disclosure surfaces (skills, subagents — `loading: on_invocation`) count by their `name` + `description` metadata only (what's injected at startup, not the body); recalled/conditional surfaces (`loading: on_demand` / `discoverable` — on-demand rules, recalled memory siblings) are excluded. A repo with many skills, subagents, or rules, or a large memory archive, is no longer flagged for context it doesn't carry every round.
- classify: agent memory entries now carry a per-entry loading model — `MEMORY.md` is the eager index (`loading: session_start`) and its sibling `*.md` notes are recalled on demand (`loading: on_demand`), matching how Claude and Gemini actually load memory.
- rules: corrected the Gemini `memory` surface in the bundled agent config against gemini-cli source — the removed `save_memory` / "Gemini Added Memories" section model is retired; the stable private memory is the `~/.gemini/tmp/<project-id>/memory/MEMORY.md` lean index plus on-demand sibling notes, the same index-and-recall shape as Claude.
- rules: instruction-size limits are now agent-aware. Generic `CORE:E:0001` (total instruction size) is an advisory **warning** rather than an error — most agents only soft-cap their always-loaded instructions. A new `CODEX:E:0001` supersedes it for Codex with a hard **error** at 32 KiB, because Codex silently truncates its combined `AGENTS.md` chain past `project_doc_max_bytes` (32 KiB default) and the overflow never reaches the model — so the rule flags the chain before content is dropped.

### Fixed

- check: backtick-wrapped tokens like `` `@pytest.mark.parametrize` `` are no longer mis-detected as `@<path>` imports, eliminating spurious "Unresolved imports" findings. The import-targets and import-depth checks now share the mapper's canonical import-reference regex (`IMPORT_REF_RE`), which excludes inline code, emails, and non-path `@tokens` — so detection matches what the harness actually expands.
- daemon/mcp: resident embedding + spaCy models are now released when idle, so a background `ails` process no longer pins gigabytes of memory indefinitely. The mapper daemon's idle shutdown is on by default (30 min; set `AILS_DAEMON_IDLE_S` seconds to tune, `0` to disable) and unloads models before exit. The long-lived MCP server now drops resident models after an idle window (`AILS_MCP_IDLE_S` seconds, default 30 min, `0` disables) and lazily reloads them on the next tool call. Both paths are cross-platform.
- mcp: the generated `uvx` MCP-server invocation now uses `--refresh-package reporails-cli` instead of a blanket `--refresh` — the server still picks up CLI updates on spawn, but no longer re-resolves the entire dependency graph each time, which pegged a CPU core under frequent respawns.
- npm: the `npx @reporails/cli` wrapper now passes `--refresh-package reporails-cli` instead of a blanket `--refresh` to `uvx`, so every `npx` invocation no longer re-resolves the whole dependency graph (the same CPU-pegging fix already applied to the MCP-server invocation). The CLI package itself is still refreshed each run.
- check: a wall-clock backstop now aborts an `ails check` that runs past a ceiling (default 600 s; `AILS_CHECK_TIMEOUT_S` seconds, `0` disables) instead of hanging indefinitely. POSIX-only (`SIGALRM`); a no-op on Windows.
- check: `ails check file:<path>` now resolves the remainder as a path instead of failing with `Error: capability file is not declared`. The `file:` scheme is the explicit inverse of `capability:name` — it forces path interpretation, so a file whose name collides with a capability noun (e.g. `file:skills`) still scans as a file. Works with relative and absolute paths.
- check: bare capability nouns (`ails check skills`, `ails check agents`) resolve to every instance of that capability for the detected agent — the all-of-kind form, equivalent to a `capability:name` spec with the name omitted. A token that is neither a known capability nor a `capability:name` spec resolves as a path; tab-completion offers both the bare noun and the `capability:` form.
- check: `ails check <file>` on a single file now classifies and lints that file instead of reporting "✓ No findings." The file path was flowing down as the classification + display root, where a directory is expected: `relative_to(scan_root)` fell back to the absolute path, the `**/CLAUDE.md` glob could not match it, the file received no `file_type`, and no rules applied. The scan now keeps the real project root and narrows discovery to the named file, so its finding path keeps its directory prefix (e.g. `.claude/rules/<name>.md`), classifies into the right group (Rules / Skills, not the generic bucket), and produces the same findings — and the same per-file priority collapse — the file gets under a whole-project scan.
- [Lint]: Gate user-scope `~/...` rendering in mechanical-check attribution on the classifier's `precedence: user` property (read from agent config patterns) instead of path-prefix heuristics, so Windows tmp paths under the user profile no longer render with a `~/` prefix.
- check: `ails check main` no longer folds subdirectory CLAUDE.md / `nested_context` / `child_instruction` files into the `main` umbrella. The capability now lists only root-level family (`main` + `override`); use `ails check nested_context` or `ails check child_instruction` to enumerate subdir CLAUDE.md. Capability-listing now reuses the classifier's `scope`/`loading` semantics so `**/CLAUDE.md` partitions correctly between root and nested.
- check: `ails check <file>` narrows the display to the named file so the headline `Score:`, surface-health bars, and per-file panels reflect only what the operator asked about. Previously, discovery enumerated user-scope `~/.claude/CLAUDE.md` alongside the project file, inflating finding totals with entries from a path the operator hadn't named.
- config: `~/.reporails/config.yml` now contributes `disabled_rules`, `exclude_dirs`, `overrides`, `rule_thresholds`, `generic_scanning`, `packages`, `agents`, and `surfaces` to the merged `ProjectConfig` (project values win on conflict; list fields extend, dict fields deep-merge under). Previously, only `default_agent`, `tier`, `auto_update_check`, and `framework_path` were read from the global file; the other field names were silently dropped at parse time, so global defaults had no effect on a project scan.
- discovery: bulk `.md` enumeration now descends into symlinked subdirectories. Previously the in-tree directory-glob path and the regex runner's whole-repo scan used `Path.rglob("*.md")`, which on Python 3.12 silently skips symlinked subdirs (`recurse_symlinks=True` is 3.13-only). Skills and rules adopted into a project via `.claude/skills/<name>` directory symlinks were therefore invisible to the classified-file set, so mechanical checks keyed on `match: {type: skill}` reported "No matching files found" and `ails check @skills` undercounted. New `core/discovery/walk.py` walker uses `os.walk(followlinks=True)` with realpath cycle tracking.
- check: declared-but-unresolved skill names in an agent's `skills:` frontmatter now print a visible stderr warning (`Warning: <agent.md> declares skill '<name>' — not found under .claude/skills/`) before the report. Previously `expand_focus()` logged the drop at DEBUG and the skill silently disappeared from the focus set, so an agent declaring a skill that was never symlinked into the project showed no signal in the diagnostics. Warning goes to stderr so JSON-format output remains structured.
- check: targeted `ails check <capability>:<name>` runs no longer surface cross-file findings from out-of-scope files. Mechanical checks that declare an `args.path` glob (e.g. `CORE:S:0056` broken-markdown-link, `CORE:S:0038` path-scope-declared) previously bypassed the capability-narrowed file set — the glob globbed the whole repo, the validation found broken links in `CLAUDE.md`, and the violation got attributed to the targeted file via the `resolve_location` wildcard fallback. The path glob is now intersected with the rule-matched, capability-narrowed classified set in `_get_target_files`, so the broken-link check sees only in-scope files. `_resolve_glob_targets` also now passes `include_hidden=True` so `**/*.md` matches `.claude/`-rooted instruction files in whole-repo runs.
- check: mapper-daemon messaging no longer prints "Starting mapper daemon..." followed by "Daemon unavailable, loading models in-process..." on the same run. `ensure_daemon()` now returns a four-valued status (`ATTACHED` / `STARTED` / `STARTING` / `UNAVAILABLE`) determined up-front via a readiness ping after fork, so the `ails check` startup banner reflects the real attach state: silent on the hot path, `"Started mapper daemon."` on a successful cold fork, `"Mapper daemon warming up, mapping in-process this run..."` when the socket binds before the daemon answers a ping, and `"Mapper daemon unavailable, mapping in-process..."` when the daemon cannot be reached at all. The genuine mid-flight failure case (daemon attached but the map call returns no result) now prints a distinct `"Daemon stopped responding, falling back to in-process..."` line instead of masquerading as a startup failure. Parent's socket-existence wait after fork is bumped from 2 s to 4 s so cold model imports do not race past the parent's timeout.
- check: `@`-references inside fenced code blocks (e.g. `ails check @main` inside a ```bash``` example) no longer get extracted as real imports, so they no longer surface as `Unresolved imports: <name>` findings under `CORE:S:0024`. The mechanical `extract_imports` and `import_depth` checks now strip fenced blocks before running the `@`-import regex, matching the fenced-block treatment already used by the mapper's `expand_imports` expander. The shared `FENCED_BLOCK_RE` lives in `core/mapper/imports.py` and is reused across both call sites so the expander and the lint check agree on what counts as documentation vs a real import.
- check: targeted runs (capability/path/file scope) no longer fire project-shape rules (`CORE:S:0010` modular-file-organization, `CORE:E:0001` total-instruction-size-limit) against the narrowed subset — these aggregate checks count the whole project, so a single-skill or single-file scope previously misreported `File count 1 outside bounds`. They are now skipped when scoped and evaluated only on whole-project scans (`ails check` / `ails check .`).
- classify: link discovery (`generic_scanning`) now extracts Markdown links whose link text is wrapped in inline code — `` [`name`](path) `` — instead of silently dropping them. The walker stripped all inline code *before* matching links, which deleted the bracket text and left `[](path)`, a form the link regex (requiring non-empty bracket text) could not match — so every backtick-wrapped reference was skipped and link-reached files went undiscovered. Inline-code stripping is replaced by a position check that skips only links wholly enclosed in a code span (literal `` `[text](path)` `` documentation examples). Two regression tests in `test_link_walker.py` cover the backtick-wrapped-link and code-example cases.
- check: `CORE:S:0015` skill-entry-point-present no longer false-fires on valid skills. It previously used a content query that asked whether a `SKILL.md`'s own body contained the literal token `SKILL.md` — which real skills never write — so every discovered skill reported `Missing skill entry point`. The rule now uses a mechanical check that enumerates each skills root and flags only directories that genuinely lack a `SKILL.md` entry file. As a whole-project aggregate it is skipped under targeted scope and evaluated on whole-project scans.
- classify: a lead-verb imperative whose parse is derailed by a long parenthetical (verb demoted to subject) is no longer misread as prose; the position-0 nsubj rescue now covers ambiguous verbs when spaCy's ROOT lands inside a parenthetical.
- classify: a sentence-initial imperative whose lead word is absent from the verb lexicon (`Pin every dependency …`, `Lock the version …`) is now charged as a directive via the determiner-object frame — a position-0 lead token governing a determiner-led object phrase with no subject. Noun-initial declaratives where the lead word is the subject of a finite verb (`Lock contention dominates …`, `Cache misses are …`) stay non-directive.
- classify: a negation inside a parenthetical (`Pin every dependency (… — never a caret range) …`) no longer flips a directive to ambiguous. The compound-instruction guard now masks parenthetical spans before scanning for a late constraint, so a subordinate clarification inside parentheses is not mistaken for a second top-level constraint clause.
- discovery: `ails check` no longer crashes with `FileNotFoundError` when an instruction-file path is a dangling symlink (e.g. a `.claude/rules/*.md` symlink whose target was removed). The exact-name and wildcard glob paths in discovery now require `is_file()`, so broken symlinks are excluded before the mapper reads file contents; valid symlinks to existing files remain discovered.
- heal: the backtick-wrap fixer no longer rewrites tokens inside markdown link labels or targets — previously `[X](X)` became the invalid-GFM form with both label and target backtick-wrapped, breaking the link render. Token occurrences outside links are still wrapped; link-only occurrences are left untouched.
- rules: `import-depth-within-limit` (cursor) re-coordinated to `CURSOR:S:0006` — its id collided with `CURSOR:S:0002` `hook-valid-event-types`, so one of the two rules was silently dropped at registry load (filesystem-order dependent). A unit test now guards global rule-ID uniqueness across the bundled corpus.
- check: a whole-project `ails check` no longer pulls in cross-project subagent memory (the global `~/.claude/agent-memory/<role>/` surface, shared across every project) — it inflated finding totals and the size aggregate with entries the current repo doesn't own. The project's own auto-memory and any repo-local `.claude/agent-memory/` stay in scope. The global surface is still lintable on demand via `ails check subagent_memory` (or `ails check memories`).
- check: `ails check memories` / `ails check subagent_memory` now report findings instead of "✓ No findings." The capability filter keyed its path set differently from the findings (absolute vs `~/`-relative form), so every out-of-tree memory target was silently dropped before display. Capability targets are now authoritative — a targeted run lints exactly the resolved files even when the whole-project scan excludes them.
- check: the per-group / per-file stats header (`N directive / N constraint · N% prose`) now renders for `ails check <dir>` and `ails check <file>` run from outside the project. The atom rollup keyed file lookup on `Path.cwd()` instead of the scan root, so any scan where the working directory differed from the target's root matched zero atoms and left the header blank.
- check: a capability target (`ails check skills`, `ails check agents`, …) on a repo with multiple detected agents and no resolved default now prints a clear `multiple agents detected (…) — pass --agent <name>` error instead of silently degrading to the `generic` agent (which produced `capability X is not declared for agent generic` or a misleading `Create a AGENTS.md`). Set `default_agent` in `.ails/config.yml` or pass `--agent` to target one agent.
- mcp: `validate(path)` on a single file now narrows discovery to that file's project root and validates only that file, instead of returning `No instruction files found`. The MCP pipeline rooted agent detection and the instruction-file walk at the file path itself (where a directory is expected), so a `{"path": "CLAUDE.md"}` call discovered nothing — the single-file narrowing already shipped for `ails check <file>` was never wired into the MCP tool.
- win: `ails` forces UTF-8 on stdout/stderr at startup so the scorecard box-drawing characters and the `-f md` arrow / em-dash glyphs no longer crash with `UnicodeEncodeError` on Windows consoles, whose default cp1252 encoding cannot represent them. The CLI ships to Windows via `npx`.

## 0.5.10

### Added
- check: Re-introduced project capability level as a `Level: L# <Label>` line in the text scorecard between `Agent:` and `Scope:`. Engine re-aligned to the canonical ladder in `docs/capability-levels.md` (System / Primer / Composite / Scoped / Delegated / Abstracted / Governed / Adaptive, L0–L7). Detection is cumulative — the displayed level is the highest where all prior levels also pass. Three new `DetectedFeatures` flags drive the new levels (`has_subagents` for L5, `has_hooks` for L6 governance, `has_auto_memory` for L7). Read-out only, not a gate; rule applicability is unchanged.
- auth: Typed `PlatformUnavailableError` raised when `/api/auth/client-id` returns a non-JSON body, replacing the silent fall-through that surfaced as a misleading "OAuth not configured" message.
- check: Per-capability targeting — `ails check <capability> <name>` resolves to a focused report on one capability target (skill, rule, agents, main, etc.), and `ails check <capability>` lists available targets with per-target scores. Capability vocabulary is read from the detected agent's `framework/rules/<agent>/config.yml` `file_types:`; supports singular and plural forms (skill/skills, rule/rules, agent/agents).
- check: Focus-mode output layout for capability runs — single-file score, findings grouped by rule with line refs, "Next" action pointer toward the highest-frequency rule. Subagent targets expand to include skills declared in their `skills:` frontmatter.
- check: `Top rules (by finding count)` block in the whole-repo scorecard, ranked across all findings.
- check: `top_rules` array in `-f json` output; `focus` envelope in capability-mode JSON describes the targeted capability, name, agent, and paths.
- check: Size-aware `CORE:S:0013 scope-fields-in-frontmatter` — rule no longer fires on rules below 30 lines (default). Override per-project via `.ails/config.yml: rule_thresholds.CORE:S:0013.min_lines`. Generic mechanism in deterministic check runner — `min_lines:` arg on any deterministic check + per-rule override.
- check: `generic` file class via Markdown link-reachability — opt-in via `.ails/config.yml: generic_scanning: true`. When on, the classifier BFS-walks outgoing links from each instruction file and assigns `file_type: "generic"` (with `loading: on_demand`) to reached in-tree `.md` files. Cycle-safe, depth-bounded (3 hops), tree-bound, agent-agnostic. Rule routing uses existing `FileMatch.type` — no rule-schema change. Default off everywhere.
- rules: `CORE:S:0056 broken-markdown-link` — mechanical rule on freeform markdown files. Discovers `[text](path)` + `[ref]: path` link targets in each file via `extract_markdown_links`, validates each resolves relative to the source file's directory via `check_markdown_link_targets_exist`. Skips URLs, `mailto:`, absolute paths, and anchor-only refs (`#frag`). Severity `medium`, sibling shape to `CORE:S:0024 import-targets-resolve`.
- check: Mechanical check engine threads `CheckResult.annotations` from a rule's discover-stage check into the args of its subsequent validate-stage check (`extract_imports` -> `check_import_targets_exist`, `extract_markdown_links` -> `check_markdown_link_targets_exist`). Annotation accumulator is per-rule; pass and fail fixtures accumulate independently in the harness. Closes a latent gap where the validate stage always saw an empty annotations dict and silently passed.
- check: Per-agent memory entry locator at `src/reporails_cli/core/discovery/memory_locator.py` — data-driven adapter that enumerates memory entries per agent (claude: `*.md` files inside `~/.claude/projects/*/memory/`, `.claude/agent-memory/<agent>/`, `.claude/agent-memory-local/<agent>/`; gemini: `## Gemini Added Memories` section inside `~/.gemini/GEMINI.md`). Returns `MemoryEntry` records with `agent`, `path`, optional `section`, and `body`. Consumed by the L3 memory rules without per-agent branches.
- classify: Link-reached generic files now record their source attribution on `ClassifiedFile.properties` — `loading_verb` ({read, imported, auto_loaded, invoked}), `link_source_type` (the linking file's `file_type` — main, rule, skill, agent, memory, subagent_memory, nested_context), `link_source_path` (project-relative paths of the linking files), and `link_depth` (1-3 from the instruction-file seed). `FileMatch` gains matching `loading_verb` and `link_source_type` fields for rule routing. Rule applicability for generic files is unchanged in this release.
- codex: New `memory` file_type declared as a tombstone — `~/.codex/memories/` holds generated state controlled via the `/memories` slash command and `config.toml` keys (`memories.generate_memories`, `memories.use_memories`, `memories.disable_on_external_context`, etc.), not user-authored markdown. No patterns to glob; surfaces in the agent registry but invites no rule pressure.
- check: Capability-name aliases for `memory|memories`, `subagent_memory|subagent_memories`, `nested_context|nested_contexts`. `ails check memory` (singular) and `ails check memories` (plural) both resolve. The memories alias folds `memory` and `subagent_memory` file_types into one listing; the main alias folds `main` and `nested_context`. Data-driven sing/plural map remains a follow-up.

### Changed
- Internals: Extracted per-item scorecard rendering (`compute_item_scores`, `render_item_health`, `_item_cell`, `_severity_breakdown_markup`, `_display_name_for_path`) from `formatters/text/scorecard.py` to `formatters/text/item_scorecard.py` so the parent module stays under the 600-line module cap per `.claude/rules/python-structure.md`. No user-visible change.
- tests: Added unit coverage for the 0.5.10 lint-pipeline scope fixes — `_strip_code_spans` (both extractors), `_resolve_glob_targets` exclude_dirs filtering, `_relativize` home-prefix fallback, `_first_classified_path` project-scope preference. 15 new tests in `tests/unit/test_lint_pipeline_scope.py`.
- auth: Set explicit `User-Agent: reporails-cli/<version> (auth)` header on platform and GitHub requests so identifiable CLI traffic can be allow-listed at the edge.
- check: `[PATH]` positional argument is now `[ARG1] [ARG2]` — `ARG1` is sniffed as a capability keyword first, falling through to existing path semantics. No behaviour change for `ails check`, `ails check .`, or `ails check <path>`.
- agents: Added `CORE:S:0024 import-targets-resolve` to `codex` and `copilot` agent `excludes:` lists — neither agent's instruction files support `@<path>` import syntax per their official documentation, so the rule has no antipattern to detect in those agents.
- rules: `CORE:S:0024 import-targets-resolve`, `CORE:S:0033 import-depth-within-limit`, and `CORE:S:0056 broken-markdown-link` severity raised from `medium` to `high` — broken includes, links, and over-depth chains are functional context gaps (referenced content silently fails to load), not stylistic warnings. `CLAUDE:S:0010` and `CURSOR:S:0002` per-agent supersedes updated to match.
- check: There is one display. Capability args (`ails check <capability>`, `ails check <capability> <name>`) narrow the input to that subset; the standard whole-repo renderer prints the same shape with fewer rows. The `formatters/text/focus.py` module was dropped; filters live in `display.py` next to the renderer that uses them.
- check: Filter the result's aggregate `quality.compliance_band` to the subset majority when capability args narrow the display. Previously the band leaked from the whole project, so the top `Score:` used the project-wide base while the per-surface health row used the filtered base — the two scores disagreed.
- check: Surface-health row is suppressed when only one surface has data (single capability target / single-surface listing). The top `Score:` already represents that surface; a second bar would just restate it.
- check: Per-item health bars in capability listings — `ails check skills` / `ails check rules` / `ails check agents` etc. now render one bar per item (sorted worst-first) where the whole-repo view would render per-surface bars. Operator can see at a glance which item is the worst. One item per line — scannable top-down without horizontal eye movement.
- check: Each item-health row carries a finding-count breakdown `(N: Xe/Yw/Zi)` after the score — severity-colored, zero counts omitted. Operator sees both severity (the bar) and effort (the count) on one line, so they can distinguish "low score but only 3 findings" from "low score, 54 findings."
- check: Score bars (top `Score:`, surface health, item health) split the markup span at the fill boundary — filled `▓` in the score color, empty `░` in dim gray. Previously the entire bar inherited the score color so empty segments looked like muted red/yellow; now every bar shares a consistent gray baseline and only the colored fill varies.
- check: Item-health listing inserts a blank line between severity bands (red → yellow → green) so the eye chunks the list into "needs attention" / "moderate" / "healthy" clusters without adding excessive whitespace.

### Fixed
- check: `CORE:S:0056 broken-markdown-link` and the generic-class link walker now strip fenced code blocks and inline code spans before extracting `[text](path)` references. Previously the rule false-positived on documentation that mentioned link syntax inside backticks — e.g. a `CHANGELOG.md` entry describing `[text](path)` semantics reported a broken link to `path`. Code-span stripping mirrors between `core/lint/mechanical/checks_advanced.py` and `core/classify/link_walker.py` so the broken-target rule and the generic-class classifier agree on what counts as a real link.
- check: Mechanical-check glob targets honor `.ails/config.yml: exclude_dirs`. Previously `_resolve_glob_targets` in `core/lint/mechanical/checks.py` globbed `**/*.md` (and similar patterns declared in `checks.yml` `args.path`) against the project root without applying the project's exclude_dirs filter, so files under excluded directories like `specs/` and `docs/` got scanned by rules that hard-code their own path glob. Project exclude_dirs are now loaded once per root and filtered against every glob result.
- check: Mechanical violation attribution no longer points to `~/.claude/CLAUDE.md` (or any user/managed-scope file) when the project has no project-scope main. `_first_classified_path` and the wildcard-match fallback in `core/lint/mechanical/runner.py` skip user-scope and managed-scope files; `_relativize` now emits `~/<path>` for paths under the home directory instead of bare basename, matching `normalize_finding_path`. Project-wide rules (`CORE:E:0001 total-instruction-size-limit`, `CORE:S:0024 import-targets-resolve`) now attribute to a project-scope file when one exists, and surface honestly when none does.
- gemini: `memory` block replaced the retired `## Gemini Added Memories` in-section locator with the current upstream model — private project memory at `~/.gemini/tmp/*/memory/` (`MEMORY.md` + sibling `*.md` notes), mirroring Claude's directory-glob shape. The legacy section header has 0 occurrences in `google-gemini/gemini-cli` source; the locator was targeting a surface that no longer exists. `memory_locator` enumerates entries through the same directory-glob dispatch Claude uses.
- gemini: All `source:` URLs in the agent config now point to the rendered `geminicli.com` docs site instead of GitHub raw markdown links. 13 file_types updated; no behavior change.
- check: Deterministic message text for the broad-scope client check — `client_checks._check_broad_scope` now sorts the matched broad terms before formatting the message, so output is reproducible across runs regardless of `PYTHONHASHSEED`. The set-iteration order previously caused `"Broad terms (any, integrations)"` vs `"Broad terms (integrations, any)"` drift on identical inputs.
- discovery: `DetectedFeatures.instruction_file_count` and `has_multiple_instruction_files` no longer include user-scope files like `~/.claude/CLAUDE.md`. The claude `main` file_type declares both project and user scope patterns; counting the user-scope file inflated capability gates in `policy/levels.py` (`multiple_files`, `external_references`) and L-level scoring in `policy/capability.py` for any user with a home-directory `CLAUDE.md`. Counts are now scoped to files under `target`; `_find_root_instruction` was already correctly scoped.
- discovery: Directory-glob patterns (trailing slash) in agent configs now enumerate `*.md` files inside the matched directories. Previously `categorize_file_type` bucketed them as `skip`, leaving capability-owned memory files unclassified — the link walker then mis-tagged them `file_type: "generic"`. Affects claude `memory` and `subagent_memory` (project + local scopes); files under `.claude/agent-memory/<agent>/` and `.claude/agent-memory-local/<agent>/` now correctly classify to `subagent_memory`, unblocking `match: {type: memory}` rule routing.
- check: `import-targets-resolve` (CORE:S:0024) fixture and rule body switched from incorrect `@import <path>` syntax (which extracted `@import` as the path) to canonical `@<path>` syntax matching the `@[\w./-]+` regex in `extract_imports`. The pre-existing fixture silently passed because the engine's annotation-threading was broken; both are now correct.
- check: Mapper daemon now stays attached across `ails check` invocations instead of forcing every run to load ML models in-process. Three issues in `core/mapper/daemon.py`: `is_daemon_running` requires the socket file to exist alongside the PID (a stuck `ails check`-turned-daemon used to keep its PID alive indefinitely, fooling every new run into seeing a "running" daemon and falling back); `_become_daemon`'s FD-close loop narrowed to FIFO/pipe FDs via `S_ISFIFO` instead of indiscriminate `range(3, 1024)` — closing all FDs killed numpy / onnxruntime compiled-extension FDs imported pre-fork, breaking the daemon's first `map_ruleset` with `ImportError: import numpy failed`; SIGPIPE set to `SIG_IGN` in `_daemon_main` so a client disconnect mid-response can't terminate the daemon via the default signal handler. Warm `ails check` against a 27-file sample now runs ~5.6 s daemon-attached instead of falling through to ~8-9 s in-process.
- discovery: `walk_glob` in `core/discovery/agent_discovery.py` now follows symlinked directories during descendant traversal so files inside symlinked subdirs are visible to whole-repo discovery. Cycle protection via canonical inode tracking ensures each physical directory is entered at most once. Aligns whole-repo discovery with the `glob.glob(..., recursive=True)` behavior used by per-capability listing.
- rules: `CORE:S:0024 import-targets-resolve` and `CORE:S:0056 broken-markdown-link` now declare `match: {format: [freeform, frontmatter]}` so they fire on SKILL.md / `.claude/agents/*.md` / `.claude/rules/*.md` files. Prior `{format: freeform}` constraint excluded frontmatter-bearing instruction files from import-resolution and broken-link coverage even though the agent schema characterizes those file types as `format: [frontmatter, freeform]`.
- tests: Wrapped the `TestWalkGlobFollowsSymlinkedDirs` class docstring in `tests/unit/test_symlink_detection.py` to satisfy `ruff` E501; no behavior change.
- discovery: Capability-listing path (`ails check <capability>`) now honors `.ails/config.yml: exclude_dirs` — `list_capability_targets` accepts and applies the exclude set, mirroring the whole-repo discovery filter. Previously the listing bypassed the config and surfaced matches inside excluded directories.
- discovery: `ails check memory` (and `memories`) now enumerates `~/.claude/projects/<hash>/memory/` entries via `memory_locator.memory_entries_for_agent` instead of returning 0 — the glob path silently dropped user-scope patterns starting with `~/`.

### Removed
- framework: Dropped `framework/registry/levels.yml` and `framework/schemas/levels.schema.yml`. The level engine has hardcoded `LEVEL_CAPS` in `core/platform/policy/levels.py` since v4 of the levels schema; the YAML file was bundled into wheels but never read at runtime. The `framework/registry/` directory is removed entirely. `hatch_build.py` no longer force-includes the path.

## 0.5.9

### Added

- Tooling: `uv run poe specs_check` validates internal subsystem coverage (declared subsystems exist, each spec is within line-budget, modules colocate under one subpackage); `uv run poe spec_drift` flags potentially stale design docs whose source has been edited more recently
- Tooling: expanded `pytest` marker taxonomy in `pyproject.toml` for granular test selection (lane, cost, subsystem) with new poe tasks `test_fast`, `test_arch`, `test_contracts`, `test_markers`
- Tooling: every `tests/*` test function now carries pytest lane (`unit`/`integration`/`e2e`) + subsystem (`subsys_*`) markers; `check_test_markers.py` enforces tagging on every `qa_fast` run, enabling `pytest -m subsys_caching` and similar slicing
- Tooling: hexagonal platform substrate skeleton bootstrapped at `core/platform/{contract,dto,policy,adapters,runtime,config,observability,utils}` with report-only architecture tests guarding pure-layer purity and adapter boundary (`tests/unit/architecture/`)

### Changed

- Build: bundle the `en_core_web_sm` spaCy pipeline (~15 MB) inside the wheel under `bundled/spacy/`, alongside the existing bundled ONNX embedder. `core/mapper/models.py` loads the pipeline by local filesystem path. End users no longer need a separate model download — `pip install reporails-cli` (or `uv pip install`, or `npx @reporails/cli`) delivers the full model bundle.
- Build: tightened `requires-python` to `>=3.12,<3.14`; Python 3.14 ships a `pydantic.v1` introspection regression that breaks `import spacy`. The CLI's verb-lexicon fallback covered the failure silently but with reduced precision. The pin restores spaCy classification under `uv sync`.
- API client: outgoing diagnostic requests now carry a `User-Agent: reporails-cli/<version>` header for accurate attribution in server-side logs; previously the generic `python-httpx/<version>` default was sent.
- Funnel: rate-limit CTA surfaces a "Try again in ~N min." hint when the server returns `reset_in`, between the limit blurb and the upgrade prompt.
- Funnel: CTA and bug-report URLs render as OSC 8 terminal hyperlinks with a short clickable label (`github.com/reporails/cli/issues/new`) instead of dumping the full percent-encoded prefilled URL; falls back to the short label on terminals without hyperlink support.
- Funnel: demoted the "Could not parse N response body" and "Server returned N for tier=" stderr warnings to debug logging so they no longer print above the diagnostic report; reworded the `unknown_error` CTA to `Diagnostics server returned HTTP <code>`.
- Display: file rows annotate duplicates with `(+alias)` labels — symlinked surfaces show the differing path component (e.g. `mintlify (+.claude)`), same-directory content-identical pairs show the alternate filename (e.g. `AGENTS.md (+CLAUDE.md)`).
- Internals: hexagonal platform substrate consolidated under `core/platform/{contract,dto,policy,adapters,runtime,config,observability,utils}`. Every top-level `core/*.py` moved into its appropriate layer (DTOs, adapters, runtime, etc.), with a new `core/install/` subsystem for installer-related modules. Architecture tests at `tests/unit/architecture/` run in fail mode — any forbidden cross-layer import blocks the build.
- Internals: five subsystems consolidated into named subpackages — `core/cache/`, `core/funnel/`, `core/classify/`, `core/heal/`, `core/discovery/`, `core/lint/` — each matching its design boundary.
- Internals: the mapper subsystem went the furthest. `core/mapper/mapper.py` was split into one module per pipeline stage (`imports.py`, `parse.py`, `classify.py`, `annotate.py`, `embed.py`, `cluster.py`, `assemble.py`) plus shared `models.py`, `serialize.py`, `inspect.py`. The orchestration spine retains the name `core/mapper/pipeline.py`. Public import surface (`map_ruleset`, `content_hash`, `map_file`) is unchanged; callers now import via the `core.mapper` package facade.
- Internals: removed the legacy "recommended" rules-overlay machinery from `ails config set/get/list`, `GlobalConfig`/`ProjectConfig`, and `core/install/`. User-installed rule packages remain supported through the generic `packages: [...]` mechanism in `.ails/config.yml` (clone any rule pack into `.ails/packages/<name>/` or `~/.reporails/packages/<name>/`).

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception
- Discovery: skill and rule files that appear under multiple agent surfaces via symlinks (e.g. `.claude/skills/` → `.agents/skills/`) are now collapsed to one canonical entry, eliminating duplicate findings and inflated scoring

### Removed

- CLI: removed `ails map`.

## 0.5.8

### Added

- [core/payload]: New `core/payload.py` module producing a compact wire payload for HTTP transport. Reduces request body size on large projects.
- [core/funnel]: New `WIRE_MAX_BYTES_BY_TIER` table and `preflight_byte_size()` function. Local preflight returns a `payload_too_large` `FunnelError` before transmission instead of an opaque server-side 4xx.
- [framework/rules/core/description-coherence]: New rule (`CORE:C:0055`) for files loaded on invocation (skills, subagents, slash commands) whose frontmatter `description:` doesn't match the body content. Server-execution rule. Replaces the previously-stale identifier the description-mismatch diagnostic had been pointing at (`prior-as-competitor`, an unrelated rule about default behavior competition).
- [core/funnel + formatters/text]: When the server returns an unrecognized error (`unknown_error` shape), the "Did you see an error?" exit ramp now deep-links to GitHub's new-issue form with the title, a triage-ready body (environment + reproduce skeleton), and a `bug` label prefilled — turning a generic `/issues` link into a one-click filed issue. Known funnel errors (rate limit, payload-too-large) keep the plain `/issues` index because they're usage signals, not bug reports.

### Changed

- [framework/rules]: Promoted `skill-name-matches-directory` to a cross-agent rule (CORE:S:0036). Skill `name` field must be kebab-case across every agent that loads `SKILL.md` entry points.
- [framework/rules]: Promoted `skill-no-readme` to a cross-agent rule (CORE:S:0035). Skill directories must keep all documentation in `SKILL.md` — a sibling `README.md` is never loaded.
- [framework/rules]: Promoted `skill-description-length` to a cross-agent rule (CORE:S:0040). The `description` field must be present in skill frontmatter; the open standard caps it at 1024 characters, with agent-specific caps acknowledged in the rule body.
- [framework/rules]: Promoted `import-depth-within-limit` to a cross-agent rule (CORE:S:0033) following the path-scope-declared supersede pattern. CORE carries a permissive absolute ceiling (max 10) as a sanity check; CLAUDE:S:0010 supersedes with Claude's documented 5-hop `@import` hard limit; CURSOR:S:0002 supersedes with `max: 1` reflecting Cursor's single-level `@filename` model. Codex and Copilot declare `CORE:S:0033` under `excludes:` in their `config.yml` because their instruction files do not honor `@<path>` syntax. Gemini inherits the CORE ceiling unchanged.
- [framework/rules/claude]: Renamed `memory-file-within-200-lines` to `memory-file-within-size-limit` (`CLAUDE:S:0011`) — slug no longer embeds the line number, since the threshold is fundamentally agent-defined. Stays in the CLAUDE namespace: Claude is the only agent with a dedicated `MEMORY.md` file the rule's `match: {type: memory}` can check (Gemini's memory is a section in `GEMINI.md`; Copilot's is system-managed with a 28-day TTL; Codex has none; Cursor's mechanic is undocumented). Promotion to CORE was reverted — it was forward-looking but in practice would have only fired on Claude.
- [framework/rules/claude]: Raised `rule-snippet-length` (`CLAUDE:S:0009`) threshold from 100 to 200 lines and dropped severity from `medium` to `low`. Added `see_also: [CORE:C:0044, CORE:S:0019]` cross-references — when a rule file follows topic-scatter and single-topic-per-section, 200 lines is comfortably enough.
- [framework/rules/copilot]: Renamed `applyto-scope-declared` to `path-scope-declared` for slug consistency with the cross-agent `path-scope-declared` family (Claude `paths:`, Cursor `globs:`, Copilot `applyTo:`). Rule body still describes Copilot's `applyTo:` mechanic; only the slug, title, and H1 heading change.
- [framework/rules/core]: Switched the `source:` URL for the three cross-agent skill rules (`skill-no-readme`, `skill-name-matches-directory`, `skill-directory-kebab-case`) from `code.claude.com/docs/en/skills` to `agentskills.io/specification`. The open standard is the canonical source for skill conventions; Claude's docs reflect the same conventions but aren't the universal reference.
- [core/api_client]: `_lint_remote` now sends the compact wire format by default.

### Fixed

- [core/classification]: Cross-agent rules with `match: {type: scoped_rule}` and `match: {type: skill}` now fire correctly. Agent configs use plural keys (`rules:`, `skills:`) for human readability while rule-side match expressions use the singular concept names; without aliasing, those rules silently never matched any file. A `_FILE_TYPE_MATCH_ALIASES` map applied at `ClassifiedFile` construction normalizes the surface key to the match vocabulary while preserving the literal key for `surfaces.<agent>.<file_type>` lookup. Bandage solution — the proper fix is to align vocabulary in one direction (either agent configs use singular keys or rule-side `match.type` uses plural). Tracked as a follow-up.
- [core/agent_discovery]: `surfaces.<agent>.<file_type>.exclude` patterns now apply across every surface of the agent, not just the surface they were declared on. Two surfaces of the same agent commonly share patterns (e.g. `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`) — declaring an exclude on one previously left the file surfaced from the other. Discovery now collects the union of all per-surface excludes for the agent and applies it once per surface.
- [formatters/text/scorecard]: `compute_surface_scores` relativizes `ruleset_map.files[*].path` against the project root before classification. Absolute paths from the mapper were being tagged `nested` purely because their leading filesystem components inflated the `parts` count, so a project with one root-level `CLAUDE.md` was rendered as `Main (1) ... Nested (1)`. Findings (which already carry relative paths) and the mapper's file list now classify consistently.
- [interfaces/mcp]: Updated `explain` tool example coordinate from `CLAUDE:S:0011` (promoted/renamed) to `CLAUDE:S:0005` so the MCP tool description references a current rule.
- [core/mapper/daemon]: Mapper daemon's 1-hour idle timeout is now opt-in via the `AILS_DAEMON_IDLE_S` env var instead of applied by default. Without the override the daemon stays running until `ails daemon stop` or an explicit kill — matching the user expectation that "background" means "doesn't go away on its own". The previous 1-hour default caused the daemon to terminate between dev sessions, so each subsequent `ails check` paid the cold-start cost.
- [framework/rules/core]: Four server-driven diagnostics that displayed unrelated rules via `ails explain` are now pointed at coherent rules. `description-mismatch` → new `CORE:C:0055` `description-coherence` (was the unrelated `prior-as-competitor`). `overall-strength` → `CORE:C:0053` `ideal-instruction`, the existing composite-rollup rule whose own Limitations describes it as such (was `compound-weakness`, which is per-atom multiplicative, not file-level). `named-coverage` → `CORE:C:0042` `specificity-gap` (was `specificity-shields`, which scopes itself to prose-heavy files; the diagnostic fires regardless of prose). `orphan` stays at `CORE:C:0053` (the existing mapping was correct — `ideal-instruction` Fix bullet #3 names the golden pattern explicitly). Also dropped two dead `RULE_ID_MAP` entries (`cross-conflict`, `cross-repetition`) that were never reachable — cross-file findings carry their own `finding_type` and never go through the diagnostic-label translation.

## 0.5.7

### Added

- [framework/schemas/project.schema.yml]: New `surfaces` and `agents` keys for `.ails/config.yml`. `surfaces.<agent>.<file_type>.include` / `.exclude` adjusts which globs each agent surface scans without modifying bundled configs. `agents.<id>.fallback_filenames` mirrors Codex `project_doc_fallback_filenames` so per-project alternative instruction filenames (e.g. `TEAM_GUIDE.md`) are picked up by the validator.
- [core/config]: `.ails/config.local.yml` (gitignored) layers on top of committed `.ails/config.yml` for personal/CI overrides — object keys merge recursively, array keys extend, scalars replace.
- [interfaces/cli/config_command]: `ails config set` writes `.ails/.gitignore` listing `.gitignore` itself and `config.local.yml` whenever `.ails/config.yml` is created/updated, so layered local config stays out of version control by default.
- [framework/rules]: `nested_context` declarations for codex / cursor / copilot / generic agents so per-package `**/AGENTS.md` files in monorepos are surfaced under the agent's on-demand loading model rather than skipped.
- [formatters/text]: Surface classifier distinguishes `main` (root-level instruction file) from `nested` (subdirectory copies). Scorecard shows a separate "Nested" section; nested file paths display the full relative path (`packages/web/CLAUDE.md`) so users can locate them.

### Changed

- [framework/schemas]: Added `scope: nested` to the `agent.schema.yml` and `rule.schema.yml` enums. Captures surfaces whose subtree applicability comes from file LOCATION (subdirectory CLAUDE.md / AGENTS.md / GEMINI.md) rather than from in-file frontmatter. Replaces the previous overload of `scope: path_scoped` for these surfaces.
- [core/agent_discovery]: Project root for `ails check <path>` is now `<path>` itself — no walking up. Files outside the targeted subtree are out of scope, regardless of `.git` or `.ails/backbone.yml` location. `engine_helpers._find_project_root` continues to walk up for cache key derivation only and now also recognizes IDE workspace markers (`.vscode/`, `.idea/`, `.github/`) as project-root signals.
- [core/agent_discovery + core/agents]: Filename matching for agent instruction files is now case-sensitive, matching Codex's source (`codex-rs/core/src/agents_md.rs` — `DEFAULT_AGENTS_MD_FILENAME = "AGENTS.md"`, `LOCAL_AGENTS_MD_FILENAME = "AGENTS.override.md"`) and the agents.md spec. A file named `agents.md` (lowercase, no leading dot) is no longer falsely surfaced as a Codex AGENTS.md candidate.
- [framework/rules/cursor]: `cursor.rules` corrected to `scope: path_scoped` (frontmatter-based path filtering); `cursor.bugbot_rules` to `scope: global` (BugBot decides applicability).

### Fixed

- [core/classification + core/agent_discovery]: Instruction-file discovery and classification now correctly distinguish `main` files at the user's target from `nested_context` / `child_instruction` files in subdirectories. Per-package CLAUDE.md / AGENTS.md / GEMINI.md files in monorepos are classified as `nested_context` rather than `main`, so size and other `match: {type: main}` rules no longer false-positive on per-package nested files. Bug surfaced against [activepieces/activepieces](https://github.com/activepieces/activepieces).
- [core/registry]: `depends_on` resolves through supersession. When `CODEX:S:0003 supersedes CORE:S:0027`, rules that depend on `CORE:S:0027` (e.g., `CORE:S:0030`, `CORE:G:0006`) are satisfied by `CODEX:S:0003` instead of warning that the dependency is "not loaded". `_apply_supersession` returns a `{superseded_id: successor_id}` map; `_validate_depends_on` consults it before emitting the missing-dependency warning.
- [core/classification]: `_location_matches_mode` distinguishes "loose" leaf patterns (`**/CLAUDE.md`, bare `CLAUDE.md`) from "tight" path-prefixed patterns (`.github/copilot-instructions.md`). Path-prefixed patterns already constrain location via the prefix, so the ancestor-chain check is skipped — fixes false-negative classification of Copilot's `.github/copilot-instructions.md`.
- [tests/unit/test_scan_scope]: `test_codex_fallback_filenames_surface` now creates `.codex/config.toml` in the fixture so codex passes the codex/generic disambiguation deterministically — was HOME-dependent (locally `~/.codex/` let codex through, fresh CI runners without `~/.codex/` dropped codex and the fallback patterns never fired).

## 0.5.6

### Added

- [docs]: Public documentation under `cli/docs/` — index, getting-started, agent-support, configuration, tiers, score-guide, faq. Vocabulary uses anonymous vs. signed in throughout (replaces earlier Pro / Free / paid framing). Maturity-levels and MCP integration pages dropped — both deferred until their respective redesigns land.
- [docs/tiers]: New page — side-by-side capability table for anonymous vs. signed-in mode, what each limit means in practice, illustrative output for both modes plus the rate-limit assessment-box CTA, and the sign-in flow (`ails auth login` → `ails auth token`). Replaces the inline "Free vs Pro" matrix that used to live in `README.md`.
- [action]: `api-key` and `server-url` inputs on the GitHub Action wrapper, passed through to the `ails check` step as `AILS_API_KEY` / `AILS_SERVER_URL` env vars — enables authenticated full diagnostics in CI.
- [pre-release]: Config + README sync step in `scripts/pre-release-check.sh` (`check-config-sync.sh`) — fails the release when `pyproject.toml` and `packages/npm/package.json` diverge on shared metadata (version, description, keywords, homepage, bug tracker, repository) or when the README's first heading is missing the version label `(vX.Y.Z)`.
- [framework/rules/claude]: `scheduled_tasks` file_type pointing at `~/.claude/scheduled-tasks/**/SKILL.md`.
- [framework/rules/claude]: `Setup` event added to `hook-valid-event-types` regex (29 total events, was 28).
- [core/funnel]: New module — `FunnelError`, `LintResponse`, `parse_error_body`, `preflight_oversized`, `merge_utm`, `format_cta`. Centralises the conversion-funnel error shape so server 4xx bodies and local preflight rejections render the same assessment-box CTA.
- [formatters/text]: Assessment-box renders a tier-and-error-aware CTA when a `FunnelError` is present. UTM-tags every CTA URL via `merge_utm`. A secondary "Did you see an error? Let us know: <BUG_REPORT_URL>" line renders below the upgrade CTA so failures always carry an exit ramp to GitHub issues.
- [core/api_client]: Universal-cap preflight (atom / file / cluster counts) saves an HTTP round-trip when the payload would be hard-rejected regardless of tier.
- [core/api_client]: Empty-files short-circuit. When the mapper returns no instruction files, `_lint_remote` skips the HTTP round-trip.
- [tests/unit/test_funnel]: Unit tests covering `parse_error_body`, `preflight_oversized`, `merge_utm`, `format_cta`, and `LintResponse`.
- [tests/unit/test_api_client]: `test_lint_skips_http_when_no_files` — regression guard for the empty-payload short-circuit.
- [auth_command]: `ails auth token` subcommand. Prints the stored API key to stdout for CI export — pipes cleanly into `AILS_API_KEY=$(ails auth token)`. Exits non-zero when not authenticated so scripts can detect missing credentials.
- [CONTRIBUTING.md]: New community-health file with contribution preamble.

### Changed

- [framework/rules/gemini]: `hook-handler-has-type` regex tightened to `command` only — Gemini docs explicitly state `prompt` is not a supported hook type.
- [framework/rules/copilot]: `hook-handler-has-type` regex tightened to `command` only — VS Code Copilot docs explicitly state `prompt` is not a supported hook type.
- [framework/rules/copilot]: `hook-valid-event-types` regex reduced to the 8 PascalCase events documented by VS Code Copilot.
- [framework/rules/cursor]: `hook-valid-event-types` rule narrative corrected from "18 events" to "20 events" — regex already covers the full 20-event Cursor set per `cursor.com/docs/hooks`.
- [core/funnel]: Conversion-CTA messages reflect the operational two-tier model. Anonymous CTAs point at `ails auth login`; signed-in CTAs route to GitHub issues for use-case escalation.
- [README.md]: Trimmed to elevator-pitch length — Quick Start, showcase output, install permanently, anonymous vs signed, In CI, doc links.
- [packages/npm/README.md]: Replaced the duplicate file with a symlink to root `README.md`.
- [pre-release-check]: New `Branch ↔ version alignment` gate — if the HEAD branch is named `X.Y.Z`, `pyproject.toml` version must equal the branch name.

### Verified

- [framework/rules/codex]: Hook regexes audited against `developers.openai.com/codex/hooks`. `hook-handler-has-type` (`type: command` only) and `hook-valid-event-types` (6 events) match the docs.
- [framework/rules/cursor]: `hook-handler-has-type` (`type: command|prompt`) confirmed against `cursor.com/docs/hooks`.
- [framework/rules/core]: Category audit run across all 91 CORE rules — 76 OK, 15 reclassifications deferred to a dedicated session.

### Fixed

- [pyproject]: `Documentation` URL no longer points at a 404. Now points at the GitHub README until the rule listing is published.
- [docs/credential-storage]: Removed the factually wrong "credentials are stored in your OS keyring" claim from `docs/faq.md`, `docs/tiers.md`, and `docs/configuration.md`. Actual storage is `~/.reporails/credentials.yml` with `chmod 0600` on POSIX.
- [core/api_client]: Preflight check rejects oversized payloads (`files`, `atoms`, `clusters`) before the HTTP round-trip.
- [core/api_client]: 4xx response bodies are now parsed and surfaced via a `LintResponse` envelope with either `.result` or `.funnel_error`.

### Removed

- [VERSION]: Deleted the orphan `cli/VERSION` file. `pyproject.toml` is the source of truth.

## 0.5.5

### Added

- Rules: Populate `backed_by` source IDs on CORE rules from `docs/sources.yml` (research evidence references)
- Rule layering: `inherited` field — child accumulates parent checks without replacing parent
- Rule layering: `depends_on` field — declare execution ordering with circular dependency detection
- Path validation: `CLAUDE.S.0012.paths_resolve` check — verifies frontmatter globs match actual files
- Schema: `source` field (URI) on rules — links to the official agent documentation a rule enforces
- Rules: CORE:S:0026 `import-references-used` — verify `@path` imports resolve to existing files
- Rules: CORE:G:0003 `permissions-ordered` — permission configuration must be present in settings
- Rules: CORE:C:0037 `static-before-dynamic` — separate stable from dynamic content with headings
- Rules: CORE:S:0031 `skill-file-length` — 500-line ceiling on `SKILL.md` files
- Rules: 22 hook rules — 5 CORE base rules with `depends_on` chain, plus agent-specific overrides for Claude, Codex, Copilot, Cursor, and Gemini
- Registry: Add `hooks` file_type to Claude config — hooks are a distinct surface from config

### Changed

- Checks: `frontmatter_valid_glob` reads `applyTo` frontmatter key for Copilot scope validation
- Schema: Migrate `Check`, `Rule`, `FileMatch`, `FileTypeDeclaration`, `ClassifiedFile` from dataclasses to Pydantic models
- Schema: `rule.schema.yml` v0.7.0 → v0.8.0 — added 9 missing check functions, `inherited`, `depends_on`, check-level `replaces`/`severity`/`message`
- Schema: Remove `overrides` from `agent.schema.yml` — severity overrides are a project-level setting
- Project: Fix stale `docs/specs/` references in `backbone.yml`, `CLAUDE.md`, `discover.py`
- Rules: Fix type mismatches in CORE:S:0018, CORE:S:0022; missing args in CLAUDE:S:0003
- Rules: Downgrade CORE:S:0017 `self-contained-skills` to low severity, accept alternative heading names
- Rules: Downgrade CORE:S:0022 `local-override-file` to low severity (override file is optional)
- Rules: 5 Claude hook rules rewritten — recognized event names, handler types, and `$CLAUDE_PROJECT_DIR` use
- Rules: Renamed Claude skill slugs and Codex slugs (clean names replace sentence fragments)
- Rules: 12 project-level CORE rules narrowed to `match: {type: main}` — fixes false positives on agent and skill files
- Sources: Move official agent documentation references from `backed_by` into per-rule `source` URLs
- Registry: Fix Claude memory cardinality `singleton` → `collection`, add rules domain field
- Repo hygiene: Add `.ignore` at repo root so Claude Code does not index test fixtures as real configuration
- CI: Add `windows-latest` to CI matrix — run lint, type check, and tests on both Ubuntu and Windows
- Tests: Skip symlink tests on Windows (require admin/Developer Mode)

### Fixed

- Regex engine: Replace POSIX-only `signal.SIGALRM` timeout with cross-platform `_timeout_guard` context manager — fixes `AttributeError` crash on Windows (#17)
- Daemon: Add `sys.platform` guards to `start_daemon`, `stop_daemon`, and daemon client for `os.fork`/`fcntl`/`AF_UNIX` — clear error message on Windows instead of raw `ImportError`
- Auth: Guard `chmod(0o600)` on credentials file — warn on Windows where NTFS ACLs don't support mode bits
- Self-update: Fix ephemeral install detection to check Windows `uv\tools\` path
- Rules: Fix double-negation patterns in 5 Claude hook rules (`expect: absent` + `pattern-not-regex` → `expect: present` + `pattern-regex`)
- Rules: Fix broken `byte_size` check on CLAUDE:S:0003 — replaced with `description` field presence check

### Removed

- Remove CORE:M:0001 `freshness-marker` — no agent documentation supports it

## 0.5.4

### Added

- Per-surface health scores with file counts in scorecard
- Rule inheritance via `supersedes` — agent rules inherit and optionally replace CORE checks
- Check-level `replaces`, `severity`, `message` override fields; `Severity.LOW` and `Severity.INFO` levels
- `frontmatter_extra_keys` mechanical check — warns when frontmatter has keys the agent ignores
- CLAUDE:S:0012 path-scope-declared — detects `globs:` misuse, enforces `paths:` as the correct key
- CURSOR:S:0001 and COPILOT:S:0001 path-scope-declared with `supersedes: CORE:S:0038`

### Fixed

- Charge classifier misses for `append`, `stage`, `compose` and 5 other verbs; ambiguous/nsubj verb rescue at position 0
- Quote-scope-aware sentence splitting — don't split inside quoted or parenthetical spans
- Backtick filter false positives on position-0 verbs appearing in later backtick spans
- M-probe pipeline skipped deterministic checks in mixed-type rules; mechanical and deterministic checks now use `match_files()` for full property-based targeting
- Show progress output during mapper startup — fixes silent hang on projects with instruction files
- Add default `exclude_dirs` to prevent walking massive non-instruction trees
- CORE:S:0038 made agent-agnostic with plain test fixtures

## 0.5.3

### Added

- `ails update` command — upgrades CLI to latest version via `uv tool upgrade`
- `ails install` now installs `ails` to PATH (via `uv tool install`) in addition to MCP config
- MCP config uses direct binary path when available (faster startup, works offline)

### Changed

- Global mapper daemon — single process at `~/.reporails/daemon/` serves all projects (~1GB RAM saved per additional project)
- Map cache moved to `~/.reporails/cache/map-cache.json` with LRU eviction (cap 5000)
- Per-project caches moved to `~/.reporails/cache/projects/<hash>/`
- `ails daemon start/stop/status` no longer require a path argument (daemon is global, path arg deprecated)
- Project `.ails/` directory is now config-only — no runtime artifacts written there

### Fixed

- Eliminate charge inversions in classifier — compound instructions ("Use X. Do not Y") now marked AMBIGUOUS instead of wrongly charged (0.30% → 0.03% inversion rate)
- Colon-label rescue for "Label: Use X" / "Label: Never Y" patterns previously neutralized as headings
- Add "pass" to ambiguous verb set — prevents status labels from triggering imperative classification
- Late-constraint guard catches negation after sentence/clause boundaries in imperative-classified atoms

## 0.5.2

### Added

- Inline Pro diagnostic counts per file card — free tier shows `⊕ N Pro diagnostics (K errors)` inside each file card instead of a separate Hints section
- Cross-file coordinate section — free tier shows which files interact (file ↔ file, type, count) without line-level detail
- Pro diagnostic counts in scorecard — `+ N Pro diagnostics (K errors · M warnings)` shows scale of findings available with upgrade
- Integrated CTA — `See all N findings with fixes → ails auth login` replaces the previous dim afterthought
- `reporails-cli` script alias in `pyproject.toml` — `uvx reporails-cli check` now works
- Entry point verification gate in `scripts/pre-release-check.sh`

### Changed

- Extract display logic from `interfaces/cli/main.py` into `formatters/text/display.py`, `display_constants.py`, and `scorecard.py` — eliminates 12 pylint structural violations, reduces `main.py` from 1118 to 315 lines
- Replace Hints section with inline per-file Pro diagnostic counts and cross-file coordinates — interaction diagnostics shown in context, not disconnected
- Mapper daemon closes inherited FDs before daemonizing — prevents parent process (npx, CI) from hanging on pipe EOF
- Mapper daemon detects orphaned state (PPID=1) and shuts down within 30s — prevents indefinite persistence after ephemeral parent exits
- Fail-fast audit — add `logger.warning()` on 4 critical-path catches, narrow 12 bare `except Exception:` to specific types, justify 16 remaining with inline comments
- Scrub internal notation from code comments and docstrings
- Rewrite READMEs for 0.5.x — current output format, correct flags, five categories
- Update tier spec — cross-file from "Blocked" to "Coordinate" for free tier

### Fixed

- Pre-compile `KNOWN_CODE_TOKENS` regex as single alternation pattern at module level — eliminates ~26,500 `re.compile()` calls per typical run
- Fix `ails map` crash when agent config files exist outside project directory (`~/.claude/settings.json`)
- Add `scikit-learn` to runtime dependencies — required by mapper topic clustering
- Fix `uvx reporails-cli` — add `reporails-cli` script alias so `uvx` resolves the executable
- Fix post-publish smoke test — use `uvx --from reporails-cli ails` instead of `uvx reporails-cli`
- Log warning when mapper fails instead of silent degradation
- Fix duplicate Install section in README, align npm description

## 0.5.1

Patch release — 0.5.0 published with a direct URL dependency (`en-core-web-sm`) that PyPI accepted but pip/uvx cannot resolve. The spaCy language model is now auto-downloaded on first run instead of declared as a dependency.

## 0.5.0

### Self-contained install

Rules, schemas, and agent configs are now bundled inside the Python wheel. `ails check` works immediately after `pip install reporails-cli` — no `ails install` step, no external rules download. The 222 bundled rule files ship as package data via hatch `force-include`. The separate `rules/` repo is no longer a runtime dependency.

### New pipeline architecture

The check pipeline was rebuilt from scratch: discover files → run mechanical probes → map instruction content → run client checks → merge results. Findings from all sources converge into a single `CombinedResult` with normalized file paths, deduplication, and per-file grouping. The old `engine.py` / `pipeline.py` / `scorer.py` stack is removed.

### ONNX embeddings (no torch)

`sentence-transformers` and PyTorch are replaced by a bundled ONNX export of `all-MiniLM-L6-v2` loaded via `onnxruntime` + `tokenizers`. The embedding output is bit-identical to the PyTorch baseline. A `sys.meta_path` import hook blocks `torch` from loading through spaCy's thinc backend, eliminating a 20-second cold-start penalty. The installed venv footprint drops by several hundred MB.

### Mapper daemon

A persistent background process (`ails daemon start`) keeps the embedding model loaded between runs. The daemon binds its Unix socket before model warmup and warms in a background thread, so cache-hit requests return instantly. Per-file embedding results are cached by content hash. Idle timeout is 1 hour (configurable via `AILS_DAEMON_IDLE_S`).

### Content-quality checks

25 rules migrated from regex pattern matching to atom-based content queries. The mapper classifies each instruction into atoms with charge (directive/constraint/neutral/ambiguous), modality, and specificity. Content queries like `has_non_italic_constraints`, `has_mermaid_blocks`, and `has_charged_headings` run against the atom map. A new `heading-as-instruction` rule flags headings that carry charge instead of organizing content.

### Heal command

`ails heal [PATH]` auto-fixes instruction file issues. Four mechanical fixers operate at the atom level: backtick wrapping for code constructs, bold→italic on constraints, full-sentence italic, and charge ordering. Reports remaining violations after fixes. Available as both CLI command and MCP tool.

### File type classification

Agent configs define file types with properties (format, cardinality, loading, scope, precedence). Rules declare which file types they target via `match: {type: ...}`. Rules that target a file type not present in the project are silently skipped — no false positives from missing surfaces. Project level is emergent from file type property coverage instead of a stored `level:` field.

### Inline import expansion

The mapper expands `@path` inline imports before tokenization. Claude Code and Gemini CLI splice imported file content at the reference position — the mapper sees the same expanded content. Resolves relative to importing file, expands `~/`, recurses up to 5 hops, detects circular imports.

### External file discovery

Agent configs can reference external paths (`~/...`, `/absolute/...`). Auto-memory files (`~/.claude/projects/*/memory/MEMORY.md`), user-level rules, and managed policies are now part of the instruction surface. Memory index validation catches broken links and missing frontmatter.

### Redesigned output

Text output redesigned — "Reporails — Diagnostics" header with file type breakdown and instruction counts (directive/constraint/ambiguous). Files grouped by type in bordered cards, sorted worst-first. Scorecard at the bottom with score bar, agent, scope, and results. JSON output grouped by file with `fix` field. GitHub formatter emits annotations with JSON summary on the last line.

### Stopwords tooling

`ails stopwords extract` parses alternation patterns from `checks.yml` into `vocab.yml` term lists. `ails stopwords sync` compiles terms back into patterns (with `--dry-run`). Staleness detection flags drift between vocab.yml and checks.yml.

### Breaking changes

- Level labels renamed: Organized→Structured, Distributed→Substantive, Contextual→Actionable, Extensible→Refined, Governed→Adaptive
- `Rule.targets` string replaced by `Rule.match` (FileMatch dataclass) with `type`, `format`, and property filters
- `rule.yml` renamed to `checks.yml` with `checks:` top-level key
- Severity moved from Check to Rule level
- Removed commands: `update`, `sync`, `topo`, `lint`, `dismiss`, `judge`
- Removed flags: `--experimental`, `--no-update-check`, `-q`
- Removed output formats: `compact`, `brief`
- `--strict` now exits 1 on any finding (was errors only)
- Project config directory renamed from `.reporails/` to `.ails/`
- JSON output schema changed: `files`/`stats` replaces `score`/`level`/`violations`

### Bug fixes

- Deterministic checks grouped by `rule.match.type` — rules with `match: {type: scoped_rule}` no longer fire on main files, eliminating ~215 false positives
- File path normalization unifies paths from all three sources (mechanical, client, server) to project-relative, fixing 60+ → 31 file key fragmentation in JSON output
- `expect: present` regex semantics inverted — was reporting matches as violations
- Duplicate findings from mechanical checks processed as regex eliminated (390 empty-message findings)
- Rich `MarkupError` crash on severity values and bracket characters in rule IDs
- Daemon JSON round-trip preserving all Atom fields
- `file_absent` false positives when match_type is set but no files of that type are classified
- Regex timeout (500ms) guards against catastrophic backtracking
- Graceful fallback when ONNX model is not bundled (CI/from-source installs)
- Score returns 0.0 instead of 10.0 when no rules checked (L0)

### GitHub Action

Action updated for the new pipeline. `parse_result.py` computes score, level, and violation count from the `CombinedResult` JSON. Invalid flags (`--no-update-check`, `-q`) removed. `--exclude-dir` corrected to `--exclude-dirs`.

### Dependencies

- Rules bundled (no external framework dependency)
- `onnxruntime>=1.18,<2`, `tokenizers>=0.19,<1` (replaces sentence-transformers + torch)
- `spacy>=3.8.11,<4` with `en_core_web_sm-3.8.0`
- `numpy>=1.26,<3`

## 0.4.0

### Multi-agent support

Agent detection and scoping overhauled. `ails check` auto-detects agents from project files — single unambiguous agent is assumed, multiple agents default to generic. Without `--agent`, only core rules load; agent-specific rules require an explicit flag. Added OpenAI Codex agent (`--agent codex`) with AGENTS.md instruction pattern, plus a generic agent config targeting AGENTS.md. Glob patterns supported in agent excludes (e.g., `CLAUDE:*`). Agent config schema v0.2.0 fields (`prefix`, `name`, `core`) now loaded.

### Configuration system

New `ails config set/get/list` commands for managing `.reporails/config.yml` without manual editing. `--global` flag writes to `~/.reporails/config.yml`. Added `default_agent` option — sets agent when `--agent` not specified (CLI flag overrides). Agent hint suggests setting `default_agent` when running generic with a specific agent detected.

### New mechanical checks

Added `file_absent` check (verifies a file does NOT exist), `count_at_most`, `count_at_least`, `check_import_targets_exist`, and `filename_matches_pattern` probes. `metadata_keys` field on the Check model enables D→M annotation propagation — D checks write matched texts to pipeline annotations, M checks read them as injected args. Check aliases registered: `file_tracked`→`git_tracked`, `memory_dir_exists`→`directory_exists`, `total_size_check`→`aggregate_byte_size`. Signal catalog aliases: `glob_match`→`file_exists`, `max_line_count`→`line_count`, `glob_count`→`file_count`.

### Test harness

Added fail scaffold system — auto-generates fail fixtures for structural M checks (`filename_matches_pattern`, `glob_count`, `file_count`, `file_absent`). Pass scaffold extended with `file_absent` support (removes forbidden file from fixture). Multi-agent prefix dispatch, effectiveness scoring, and coverage baseline added to harness.

### Scorecard redesign

Scorecard moved to bottom of output — violations shown first, score as conclusion. Category table redesigned with mini bars, centered columns, and severity-colored icons. Maturity level moved to own line below score, elapsed time shown in top-right. Semantic color output throughout — score, bar, level, violations, friction, and category table use green/yellow/red (ASCII mode disables colors). Pending semantic checks shown inline with violations using `?` icon. "Setup:" replaced with "Scope:" showing instruction files by agent directory labels.

### `ails heal` simplified

Heal command simplified to autoheal — silently applies all fixes, reports remaining violations and pending semantic rules (interactive prompts removed). Added `--format`/`-f` option (text/json) replacing `--non-interactive` flag. Dismissed violations filtered from output (cached as pass verdicts, reset with `--refresh`).

### CLI polish

- `setup` command renamed to `install` — `setup` kept as hidden alias
- `--help` groups commands into panels (Commands, Configuration, Development) — `dismiss` and `judge` hidden as plumbing
- Phased progress spinner shows "Loading rules..." / "Checking files..." / "Scoring..." during validation
- `explain` unknown rule shows rules grouped by namespace with counts instead of flat list
- Install CTA shown for ephemeral (npx/uvx) users below scorecard
- Raw exceptions wrapped in user-friendly error messages (FileNotFoundError, RuntimeError, download failures)
- Exit code 2 for input errors in `explain` and `--rules` — was exit 1
- `"partial"` evaluation label renamed to `"awaiting_semantic"` across all output formats (breaking: JSON consumers checking `evaluation` field need updating)
- "CLAUDE.md" replaced with "AI instruction files" in CLI, MCP, and setup strings

### GitHub Action improvements

- Agent default changed from `claude` to empty (resolve via project config or generic fallback)
- Added `-q` (quiet-semantic) flag for CI — no human to judge semantic rules
- Added `exclude-dir` input for comma-separated directory exclusions
- Fixed shell syntax error in step summary — JSON result passed via env var instead of shell argument

### Testing

Mutation-tested E2E smoke layer (`tests/smoke/`, 112 tests) covering agent scoping, cross-agent contamination, template context, hint messages, violation accuracy, CLI commands, mechanical checks, and flag combinations. Pipeline output stability tests with golden snapshots and regeneration flag. Unit test suite refactored — parametrized duplicates, added boundary/edge-case tests, relocated pure unit tests from integration/. GitHub Action regression workflow (`test-action.yml`) with pass/fail scenarios.

### Bug fixes

- `ails explain` did not resolve agent-namespaced rules (e.g., `CLAUDE:S:0001`) and showed "Unknown" for check labels — fixed in both CLI and MCP
- MCP tools (validate, score, heal) did not apply `exclude_dirs` from project config — was scanning all directories including test fixtures
- MCP `validate` handler missing `rules_paths` and `exclude_dirs` — called `run_validation` directly without resolving project config
- Semantic JudgmentRequests not deduplicated by file path — multiple D matches in the same file produced N evaluations instead of one
- Malformed YAML config files failed silently instead of logging warnings; malformed project config returned hardcoded defaults instead of global defaults
- Empty-files hint was hardcoded to CLAUDE.md instead of showing the correct instruction file per agent
- Unknown `--agent` values silently ignored — now error with exit code 2 and list known agents; values are case-insensitive
- Invalid `--format` values silently accepted — now error with exit code 2 and list valid formats
- `--agent generic` returned empty template context instead of file-derived vars
- JSON output serialized raw duplicate violations instead of deduplicated results
- Without `--agent`, scanned all agent files with identical rules instead of defaulting to generic
- Rule compiler crashed on `paths: include: null` in YAML rules (`dict.get()` returns `None` not default when key exists with null value)
- `exclude_dirs` config not applied during agent file discovery — test fixtures scanned as real instruction files
- `--refresh` flag only cleared semantic judgment cache, not agent or rule caches
- Mechanical checks ignored `rule.targets` — fell back to all instruction files instead of scoped targets
- `file_absent` searched from project root instead of rule target scope — project-level README.md triggered false violations for skills-scoped rules
- `disabled_rules:` with empty value in config.yml crashed with `TypeError` (`set(None)`)

### Dependencies

- Rules framework 0.5.0
- Recommended package 0.3.0
- Agent schema v0.2 compatibility

## 0.3.0

### Pure Python regex engine

Replaced the OpenGrep binary dependency with a pure Python regex engine. No external binary to download, no semgrepignore, no platform-specific builds. Includes an adversarial test suite (76 tests) validating edge cases. SARIF locations are now relative to the scan root instead of absolute paths.

### `ails heal` command

Interactive auto-fix and semantic evaluation. The auto-fix phase silently applies safe structural fixes (constraints, commands, testing sections, structure) via a registry of 5 additive fixers. Remaining semantic rules are presented for interactive pass/fail/skip/dismiss judgment. `--non-interactive` outputs JSON for coding agents and scripts. The MCP `heal` tool provides the same flow for editor integrations.

### `ails setup` command

Auto-detects agents in the project (Claude, VS Code, Codex) and writes MCP config files (`.mcp.json`, `.vscode/mcp.json`, `.codex/mcp.json`). Replaces the manual `claude mcp add` workflow. The npm wrapper now proxies `setup` instead of `install`/`uninstall`.

### GitHub Actions integration

Composite GitHub Action (`action/`) installs the CLI, runs validation, writes a step summary, and gates on score or violation count. `--format github` emits `::error`/`::warning` workflow commands for inline PR annotations.

### MCP overhaul

Validate tool returns structured JSON instead of formatted text. Semantic judgment requests carry full file content (up to 8KB) instead of 5-line snippets. Replaced the `_instructions` text blob with a structured `_semantic_workflow` object. Content-aware circuit breaker tracks file mtimes instead of a blunt call counter, allowing edit-validate cycles. Error responses use structured JSON with `error` and `message` keys. All tool descriptions rewritten with output format info and usage guidance.

### Performance

Agent detection, rule loading, glob resolution, and template binding are now cached across MCP invocations. Path-based pre-grouping avoids O(files × checks) inner loops. Combined regex patterns batch simple checks into alternation with named groups. Non-matching files are skipped before I/O. CSafeLoader used for YAML parsing when available (~3x faster).

### Bug fixes

- File discovery used project root instead of scan root — agent detection and feature scanning now scoped to target directory.
- Content rule violations attributed to root instruction file instead of skill files.
- Per-file size violations attributed to the violating file, not the rule-level target.
- Cache hash crash on non-UTF8 instruction files.
- Feature merge in agent feature lookup used overwrite instead of OR.
- Regex compiler crash on malformed rule YAML and binary YAML files.
- Mechanical checks crash on string args from YAML.
- `detect_orphan_features` crash on L0 projects (no instruction files).
- `dismiss` command wrote to wrong cache when run from subdirectory.
- Double analytics recording — engine and check command both called `record_scan`.
- MCP tools: narrowed exception handling, added `is_dir()` validation, graceful file read errors.
- MCP judge: path-traversal rejection, detailed feedback, truncated reasons in response.
- Exit code 2 for input errors, exit 1 for violations.

### Dependencies

- Rules framework 0.4.0
- Recommended package 0.2.0

## 0.2.1

### Pipeline state engine

Rules now execute through a per-rule ordered check pipeline with shared mutable state. Deterministic+semantic rules run through a single regex pass, then SARIF results are distributed to per-rule buckets for ordered check execution. Includes in-memory check result cache for cross-rule mechanical dedup and D→M annotation propagation.

### MCP judge tool

Native `judge` MCP tool enables verdict caching directly from Claude Code, with a circuit breaker to prevent infinite validate-fix-validate loops.

### Module reorganization

Split 7 oversized modules (models, cache, registry, init, engine, checks, cli/main) to stay under pylint structural limits. Stricter tooling: ruff ARG/C90/PERF/RUF rules, pylint 300-line module enforcement.

### Security hardening

- Tarball extraction now validates all archive members for path traversal and symlink attacks before extracting.
- Rules update uses atomic swap: rename old out, move new in, restore on failure.
- Post-extraction structure validation ensures expected directories (`core/`, `schemas/`) exist.
- Path traversal fix in judgment cache writes.

### Bug fixes

- Pipeline silently swallowed unknown rule types instead of warning.
- Negated check_id lost full coordinate format (split on last colon instead of preserving `check:NNNN`).
- `content_absent` crashed on invalid regex patterns.
- Broad `except Exception` in frontmatter checks swallowed unexpected errors.
- `_apply_agent_overrides` mutated shared Rule objects (Rule now frozen).
- JSON serializer omitted `content` field from JudgmentRequest output.
- Nondeterministic directory selection in recommended extraction.
- explain_tool returned empty rules (missing paths + tier filtering).
- Template vars unresolved when engine uses custom rules_paths.
- Verdict parser mangled coordinate IDs with line numbers.
- MCP server crashed on RuntimeError from init/validation.
- ScanDelta IndexError on corrupted level in analytics cache.
- Concurrent judgment cache writes lost data (now atomic).
- Recommended rules download failures silently swallowed.
- `__version__` was hardcoded and drifted from package metadata.
- `_find_project_root` walked past child backbone into parent coordination root.

## 0.2.0

### CLI self-upgrade

New `ails update --cli` command upgrades the CLI package itself. Detects the install method (uv, pip, pipx) from package metadata and runs the appropriate upgrade command. Dev/editable installs are detected and refused with a helpful message.

`ails version` now shows the detected install method.

### Recommended rules included by default

Recommended rules (AILS_ namespace) are now included in every check and auto-downloaded on first run. The `--with-recommended` flag has been removed.

To opt out, add to `.reporails/config.yml`:

```yaml
recommended: false
```

`ails update --recommended` updates recommended rules only (skips framework).

### Unified update experience

`ails update` now updates both rules framework and recommended rules in a single command. Staleness detection tracks both components with a 24-hour cached check against GitHub releases.

Before each scan, the CLI prompts when updates are available: `Install now? [Y/n]`. CLI upgrades are shown as a hint but not auto-installed. Use `--no-update-check` to skip.

`ails update --check` shows installed vs latest for both framework and recommended. `ails version` displays recommended version alongside framework.

MCP tools (`validate`, `validate_text`, `score`) now include recommended rules in validation, matching CLI behavior.

### Mechanical checks

New rule type: mechanical checks are Python-native structural checks — file existence, directory structure, byte sizes, import depth, and more. Rules of any type may contain mechanical checks alongside deterministic patterns.

### Coordinate rule IDs

Rule IDs now use 3-part coordinate format (`CORE:S:0001`) instead of short IDs (`S1`). All commands (`explain`, `dismiss`) and config files (`.reporails/config.yml`) use the new format.

### Staging for rules download

`download_rules_version()` now extracts to a staging directory, verifies schema compatibility, then swaps. Incompatible rules no longer destroy working installations.

### `--exclude-dir` flag

`ails check --exclude-dir NAME` excludes directories from scanning. Repeatable for multiple directories.

### Release pipeline

Release workflow split into two stages: CI runs QA on version branches (e.g. `0.1.4`), and the release workflow triggers on merge to main — creating the tag, GitHub release, and publishing to PyPI and npm only after QA passes.

### Cache-busting for uvx

All `uvx` invocation strings now include `--refresh` to ensure users get the latest package version instead of a stale cache.

### Bug fixes

- Fix circular symlink detection crash on Python 3.12+ (`RuntimeError` instead of `OSError`).

### Dependencies

- Rules framework 0.3.1
- Recommended package 0.1.0
