# Unreleased

### Added

- New security checks run on every instruction file each agent loads (`CLAUDE.md`, `AGENTS.md`, rules, skills, agents, commands, hooks, MCP config) and on the files they import with `@path`:
  - `CORE:G:0010` reports invisible Unicode that hides text from a reviewer while the agent still reads it: tag characters, BiDi overrides, zero-width characters and invisible operators. Emoji sequences (skin tones and flags included), joiners inside Arabic-script and Indic words, and a byte-order mark at the start of a file or of an imported file are left alone.
  - `CORE:G:0011` reports a personal home-directory path such as `/home/<name>/`, `/Users/<name>/` or `C:\Users\<name>\`. Windows system profiles such as `Public` and `Default` are left alone. Like `CORE:G:0013`, it checks committed files only, never `.claude/settings.local.json` or your own memory files.
  - `CORE:G:0012` reports a command that downloads code and runs it unseen, such as `curl … | sh`, `bash <(curl …)` or `irm … | iex`.
  - `CORE:G:0013` reports personal data: a US social security number, an international phone number, a MAC address, a public IPv4 address, a personal email address or a crypto wallet address. Version numbers, public DNS resolvers, role addresses such as `security@`, SSH targets and a declared `author` or `contact` email are left alone.
  - `CORE:G:0014` reports text that tells the agent to drop its other instructions or to hide its own actions or instructions from the user.
  - `CORE:G:0015` reports a command that reads a credential store (`~/.ssh/id_*`, `.aws/credentials`, `.netrc`, …) or uploads a local file or the environment to a remote host. Public keys, `authorized_keys` and a token written as an environment reference are left alone.
- New skill checks report a skill that some agents drop or degrade: a name over 64 characters or containing `anthropic` or `claude` (`CORE:S:0059`), a description over 1,024 characters (`CORE:S:0060`), Cursor rule fields `alwaysApply` or `globs` (`CORE:S:0061`), a duplicate frontmatter key (`CORE:S:0062`), tab indentation in the frontmatter (`CORE:S:0063`), and a frontmatter key that YAML reads as a non-string (`CORE:S:0064`).
- `ails xray` reads the agents a Claude Code Workflow run starts, with their loads and hand-backs, and a live page keeps refreshing while a run's agents work.
- `ails xray` folds every segment before the newest compaction into one band showing its loads, its agents and the context size before and after the compaction, so a long session opens at what the agent holds now. The compaction stripe still lists the files that came back and the files that did not. Selecting an agent or a call in an earlier segment opens it.
- `ails xray` draws the instruction files that one hook made Claude Code load within a quick run as one card named after that hook, with its file count and size; opening the card lists the loads. A file loaded again and again within a quick run is one card that counts the loads (for example ×21).
- `ails xray` shows a Workflow run as a node naming the workflow, its phases, status, agent count and tokens, with the run's agents under their phases; a run whose record cannot be read shows as "not readable" while the other runs and the page still load.
- `ails xray` lists every hook your settings and plugins declare in the Hooks group, not only the ones that fired, and the header reads fired/declared.
- `ails xray` says why a declared hook cannot fire: its script lost the executable bit ("never fired · not executable"), its folder is gone ("folder missing") or the script is missing ("script missing"). The group header adds "N cannot fire", and the hook's details open on a Health section with the fix, such as `chmod +x <path>`.

### Changed

- `CORE:G:0002` (No Credentials) also reports a database connection string with an inline password, a JWT, a Google API key, a Stripe live or restricted key, an npm token and a Slack webhook URL.

- Signing in raises the per-check size limit from 2 MB to 5 MB, and the too-large message says so.

- `ails check`, the MCP `validate` tool and the x-ray page parse each rule's checks once, where they parsed them again for every check run: over 20 `validate` calls the rule-file reads drop from 790 to 130. Findings are unchanged.

- `ails xray` shows what the coding agent adds to the context by itself (system prompt, tool definitions, listings, deferred tools, session context, thinking and its other messages) as one collapsed group in each agent's In context list, so Conversation holds only what you and the agent wrote. Opening an item shows the text the agent actually sent and, for the system prompt, its sections with their shares; each item has one size across the page, measured from the recorded request when there is one and labelled as an estimate otherwise. The Sources panel no longer lists these items.

- `ails check -f json` and the MCP `validate` response carry a top-level `format_version`, now `1`, which changes when the shape of that output changes. Its `not_evaluated` list can now also hold `{"file", "reason"}` items for a named target that was not checked, beside the existing `{"rule", "file"}` items.

### Fixed

- Antigravity hooks are no longer expected in `~/.gemini/antigravity-cli/settings.json`, which the Antigravity CLI does not load.

- `validate` and `ails check` now give the same answer for every named target. A folder linked from outside the project is checked for the markdown it holds. A word that is both a folder and a capability tells you which meaning was used. A capability the agent lacks is listed as not checked with its name instead of failing the call.
- A folder is only reported as holding no markdown when it holds none.
- A rule that selects files by whether they are committed, gitignored or user-level now finds them; before, such a rule matched no file.
- `ails test` runs a rule's pattern checks only on the files its `match` selects, as `ails check` does, so a rule pack's fixtures test the rule's real scope.
- A Claude Code memory file that keeps its `type` under `metadata:` no longer gets a "missing frontmatter: type" warning.
- The docs now name `AILS_API_KEY` as the environment variable the CLI reads its API key from, and show a CI job that installs the CLI with `npm` and sets it. `REPORAILS_API_KEY` in the GitHub Action examples is only an example secret name; the Action passes its `api-key` input on as `AILS_API_KEY`.
- `ails check prompts/review.md` on a markdown file no agent loads now checks it as a referenced file, with the same findings, the `Referenced` panel and no score, as when a link reaches it. `ails check ./prompts` checks the markdown files under the folder instead of printing "Create a CLAUDE.md". A folder with no markdown, a folder whose markdown files `exclude_dirs` or `exclude_files` leave out, a file that is not markdown, a capability the agent does not have, or one with no files in the project is reported by name and not checked, in the text output, the JSON `not_evaluated` list, GitHub annotations and the MCP `validate` reply. A named file an `@`-import reaches keeps its importer's class. When a word names both a capability and a folder, the output says which one it checked.
- `ails check prompts/review.md` on a markdown file no agent loads now checks it as a referenced file, with the same findings, the `Referenced` panel and no score, as when a link reaches it. `ails check ./prompts` checks the markdown files under the folder instead of printing "Create a CLAUDE.md". A folder with no markdown, a file that is not markdown, or a capability the agent does not have is reported by name and not checked. When a word names both a capability and a folder, the output says which one it checked.
- A check-level `disabled: true` override in an agent config now drops that check; before, it still ran and reported.
- A settings file without hooks is no longer reported by a rule that another rule supersedes.
- The x-ray compaction stripe's one-line text stays inside the stripe at 1280 and 1920 px instead of running past it.

### Removed

### Internal

- The x-ray graph records are split into two modules; no change in what the page shows.
- The pattern checks scan exactly the files the run checks, so the folders and files `exclude_dirs`, `exclude_files` and `--exclude-dirs` leave out stay out of them; checking one file applies its project's `.ails/config.yml` to the files that file's links reach.
- Tests: the loader refusals for an empty or uncompilable `pattern-either` and a check without an id are covered against the real loader.
