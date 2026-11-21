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

### Changed

- `CORE:G:0002` (No Credentials) also reports a database connection string with an inline password, a JWT, a Google API key, a Stripe live or restricted key, an npm token and a Slack webhook URL.

- Signing in raises the per-check size limit from 2 MB to 5 MB, and the too-large message says so.

### Fixed

- A rule that selects files by whether they are committed, gitignored or user-level now finds them; before, such a rule matched no file.
- `ails test` runs a rule's pattern checks only on the files its `match` selects, as `ails check` does, so a rule pack's fixtures test the rule's real scope.
- A Claude Code memory file that keeps its `type` under `metadata:` no longer gets a "missing frontmatter: type" warning.

### Removed

### Internal
