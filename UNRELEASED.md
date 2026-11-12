# Unreleased

### Added

- `ails check --offline` (or `AILS_OFFLINE=1`) runs local checks only and makes no network call; the summary says the server analysis did not run.

### Changed

- Heal in your agent now makes every change through your agent's own edits, so your edit approvals and hooks see each one.
- `ails check`, the MCP `validate` tool and opening `ails xray` now ask the reporails service first, before reading your files or downloading the model. When this hour's allowance is used up, or your version is no longer supported, the run stops right away and names the next step: signing up, when the allowance resets, or `ails update`.
- When the reporails service cannot be reached, `ails check` stops and tells you to run with `--offline` for local checks only.

### Fixed

- On Windows, `ails check` names a file relative to its project, finds the files of a `~/.claude` folder and keeps a linked rule inside its project when the folder is spelled with a short (8.3) name; a file in the folder the command runs in is named with `/`, not its full path.
- With a home folder reached through a link, `ails check` on a `~/.claude` folder reports that folder's findings instead of none.
- Heal in your agent leaves a line marked with `ails-disable-line` exactly as it is: the agent is given no fix and no decision on it.
- Heal puts back a rewrite that narrows what a prohibition forbids: the forbidden thing swapped for the kinds the same line names (`Do not file plans` → `Do not file X or Y`), or a new noun put in front of it (`Do not treat a recalled memory …` → `Do not treat a prior orientation — a recalled memory …`).
- Heal puts back a rewrite that gives a rule a `for` phrase it never had (`add tests` → `add tests for src/`), and a split that leaves part of a sentence outside the scope it opened with (`For all, group X, count Y` → `For all, group X. Count Y.`).
- Heal keeps a rewrite that only reorders a prohibition's words (`Do not modify X — those are Y` → `Do not modify Y: X`).
- Heal puts back a prohibition given a list of kinds it never named (`Do not file plans` → `Do not file any plan — X, Y, or Z`), or an aside turned into a qualifier (`Do not modify the docs — those are generated` → `Do not modify generated docs`); a list led by `such as` or `e.g.` still passes.
- Heal puts back a rewrite that gives a rule covering every case a list of objects (`Edit at canonical paths only` → `Edit X and Y at canonical paths only`); naming the one thing the line left implied still passes.
- Heal keeps a rewrite that moves a sentence's scope to its end (`In a monorepo, run X` → `Run X in monorepos`), names a path holding `for` (`docs/for-agents.md`), opens with `For each …`, or changes only the part of a sentence after a prohibition's dash, and reads `in-memory` as one word, not a place.
- Heal's report lists a sentence it made specific once, with every sentence it was split into, so a split no longer reads as a dropped instruction.

### Removed

- The `heal_apply` tool is removed; update the reporails plugin to its matching version.

### Internal

- The Windows check scenarios and the MCP x-ray two-call scenario lose their skip tag. The two-call scenario reads the page while the agent's MCP server still runs, because on Windows the test client ends the server's process tree, the page with it.
- Three check scenarios guard linked folders: a `.claude/rules` folder linked to a dotfiles folder stays part of `ails check .claude`, a linked file under a `~/.claude` linked to a dotfiles folder keeps its user-level root, and a `~/.claude` folder keeps its findings when the home folder is reached through a link.
