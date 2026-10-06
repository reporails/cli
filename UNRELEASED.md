# Unreleased

### Breaking changes

- `ails auth login`, `ails auth logout`, `ails auth status` and `ails auth token` are replaced by `ails login` and `ails logout`. Upgrading from 0.6.0: run `ails update`, then `ails login`.
- CI and the GitHub Action use an API key created on reporails.com/account, set as `AILS_API_KEY` (or the Action's `api-key` input); `ails auth token` is gone.

### Added

- `ails login` signs this machine in to your account through your browser: it prints a link and a short code, opens the browser when it can (also when a coding agent runs it), and finishes when you approve. One sign-in per machine, lasting a year, and your plan (Free or Pro) comes from your account, so a second machine or a CI key never affects the others. On a machine that is already signed in it shows who is signed in and on which plan, and signs in again when that sign-in has ended. Where no browser can open, as in most SSH sessions, it prints the link instead, and after too many attempts from one network it says how long to wait.
- `ails logout` signs only this machine out, and still removes the local sign-in when the website cannot be reached or the saved sign-in file is damaged.
- Messages about your account (a failed payment, Pro ending, an announcement) appear under the header of `ails check`, as a `notices` list in `--format json`, and in the MCP `validate` reply. A warning shows on every run; other messages once a day.

### Changed

- The docs cover the messages about your account (a failed payment, Pro ending) and add FAQ answers for signing back in, signing in over SSH, and CI after the move to API keys.
- Sign-in hints, `ails --help`, the npm wrapper's help and the docs point to `ails login` and `ails logout`. For CI and the GitHub Action, create an API key on reporails.com/account and set it as `AILS_API_KEY`.
- Check: the first `ails check` on a large project, before anything is cached, finishes sooner.
- Check: every `ails check` in a large repository finds its files faster: the folders it skips (`.git`, `vendor`, `node_modules` and your `exclude_dirs`) are no longer searched.

### Fixed

- A check run in the first minutes after signing in, while the sign-in is still reaching the server, says to try again in a minute instead of saying the sign-in ended.
- Check: instruction files inside symlinked folders, such as a shared rules folder linked into `.claude/rules/` or a skill folder linked into `.claude/skills/`, are found and checked.

### Removed

### Internal

- The MCP server's idle model release has its own module.
- The stored sign-in is read through one reader, and messages from the server are read off a reply and remembered once shown.
