# Unreleased

### Added

- `ails check --offline` (or `AILS_OFFLINE=1`) runs local checks only and makes no network call; the summary says the server analysis did not run.
- After a heal run through your agent, `ails check` names each healed file whose score fell or whose findings came back since the heal, one line per file (`Since the last heal: CLAUDE.md score 8.4 → 7.9; findings back: CORE:C:0058 +2`), and `--format json` carries them under `heal_regressions` and each file's score under `file_scores`.

### Changed

- Checking a rewritten file with the MCP `validate` tool now answers `accepted`: whether the rewrite is kept, so the agent no longer weighs the preservation, plan and score results itself. A rewrite whose score is missing is not accepted, and a repeated check of an unchanged file that stops at the repeat limit still answers `accepted`.
- Heal in your agent now makes every change through your agent's own edits, so your edit approvals and hooks see each one.
- `ails check`, the MCP `validate` tool and opening `ails xray` now ask the reporails service first, before reading your files or downloading the model. When this hour's allowance is used up, or your version is no longer supported, the run stops right away and names the next step: signing up, when the allowance resets, or `ails update`.
- When the reporails service cannot be reached, `ails check` stops and tells you to run with `--offline` for local checks only.
- Heal's rewrite rules now come from the reporails service, so a rewrite is always held to the current rules without a cli update.
- After a compaction, `ails xray` names each instruction file loaded before it that did not come back, as named only (the agent must read it again) or only in the summary, and the chart keeps only the files whose content is back in context, whether loaded again, attached whole, recalled or kept in the messages the compaction preserved; this works on sessions from earlier Claude Code versions too.
- The finding for a condition that names an outside system quotes the whole condition, its opening word included (`When external services fail`).
- In `ails xray` each compaction is a stripe across the canvas at its time; clicking anywhere along it opens the details window with the trigger, the context before and after, the summary text and each instruction file loaded before it that has no card below the stripe, with its state (kept in the preserved messages, settles at the next reply, named only, or only in the summary); when every file has a card it says so. The floating file list and the inspector's summary button are gone, and the inspector lists every compaction, one with no summary included, and each row opens the same window. A stripe leaves the time labels, stretch bars and the Tool calls link beneath it usable.
- In `ails xray` a compaction starts the agent's context over on the canvas: the instruction files, memory notes and MCP servers that load again after it are drawn as source cards below its stripe, as at the start of the session, and no card or station pill sits on the stripe.

### Fixed

- With the `ails xray` page open, an instruction or rule file added to the project is checked by the page's next check, with no restart of the page.
- The x-ray counts a memory note as loaded when it arrives by an `@` mention, an edit, a recall or a restore after a compaction, and notes loaded that way are listed by the next compaction; an edit adds no more than a snippet to the chart. The loads show as attached by Claude Code, and a recall row that names no notes is refused. A loaded slot chip on an agent card is clearly lit.
- The x-ray shows each compaction's summary by the transcript's own link between a compaction and its summary: a compaction that left no summary shows none, and the next compaction no longer shows its summary.
- Opening a compaction summary in the x-ray reads only that summary from the transcript, not the whole file again.
- `ails xray --current` follows a `/clear` chain on from each of several sessions cleared at the same moment, never past one into another, and opens the newest session the chains end in.
- A heal rewrite that fails the meaning check is no longer accepted after the project is re-validated mid-run.
- Heal puts back a rewrite that puts a plain word in front of what a prohibition forbids (`Never modify the docs` → `Never modify the generated docs`); a named construct there still passes.
- `ails check` no longer warns about broad conditional scope on an instruction that only limits what it acts on, such as `Use only the staging database, never production.`
- Heal runs several in-place fixes on one line (dropping two hedges, `Try to lint; perhaps run tests.`) at the right place for each: a fix that no longer finds its place after an earlier one is left for the rewrite instead of cutting into the wrong words.
- Heal no longer reports a lone `Consider` or `You should` as a lost instruction when a hedged sentence is rewritten as a direct one, and a rewrite that gives a reason (`, because ...`) or restates a condition with a pronoun is kept.
- Heal reads a phrase opened by `only`, `except`, `excluding`, `outside`, `solely` or `absent` as a condition: it puts back a rewrite that drops one or widens an exclusion, and a dropped condition is reported as a dropped condition rather than a lost instruction.
- Heal keeps a near-duplicate line flagged when a preposition differs, accepts a hedged sentence split into a directive and a prohibition that names the tool the original called "the linter", and refuses to split a line at a dash that opens a series of same-kind prohibitions.
- On Windows, `ails check` names a file relative to its project, finds the files of a `~/.claude` folder and keeps a linked rule inside its project when the folder is spelled with a short (8.3) name; a file in the folder the command runs in is named with `/`, not its full path.
- With a home folder reached through a link, `ails check` on a `~/.claude` folder reports that folder's findings instead of none.
- Heal in your agent leaves a line marked with `ails-disable-line` exactly as it is: the agent is given no fix and no decision on it.
- Heal puts back a rewrite that narrows what a prohibition forbids: the forbidden thing swapped for the kinds the same line names (`Do not file plans` → `Do not file X or Y`), or a new noun put in front of it (`Do not treat a recalled memory …` → `Do not treat a prior orientation — a recalled memory …`).
- Heal puts back a rewrite that gives a rule a `for` phrase it never had (`add tests` → `add tests for src/`), and a split that leaves part of a sentence outside the scope it opened with (`For all, group X, count Y` → `For all, group X. Count Y.`).
- Heal puts back a rewrite that adds a trailing place or time to an instruction (`Run pytest before every commit` → `Run pytest before every commit on this branch`), and one that narrows a verb that took no object (`Run at night only` → `Run shell scripts at night only`); a condition restated after another phrase (`…, whenever the build fails`) is held.
- Heal keeps a rewrite that only reorders a prohibition's words (`Do not modify X — those are Y` → `Do not modify Y: X`).
- Heal keeps a renamed instruction heading (`## Never Push Directly to Main` to `## Branching`) when the body beneath gains the same instruction, and puts back a hedge made absolute only when the author's line had no such word.
- Heal puts back a prohibition given a list of kinds it never named (`Do not file plans` → `Do not file any plan — X, Y, or Z`), or an aside turned into a qualifier (`Do not modify the docs — those are generated` → `Do not modify generated docs`); a list led by `such as` or `e.g.` still passes.
- Heal reads a rewrite's sections from the file's headings: a kind another section lists is no narrowing, a kind named beside others in the line's own section is, and a rewrite that names a place with a construct (`the changelog at CHANGES.md`) or restates a phrase in new words is kept.
- Heal keeps a rewrite that only changes the part of a prohibition after a single em or en dash (an en dash counts only with a space on each side, so `3.10–3.12` and `client–server` stay whole; a spaced ASCII hyphen does not end a prohibition, so an edit after it is put back), still reads a list set off between two dashes as part of what is forbidden while two clauses between dashes are not, does not count `Do not commit secrets` -> `Do not commit secrets or credentials` (the author's own noun stays one alternative) as a narrowing, and keeps a `(see … for …)` aside from counting as a new scope.
- Heal puts back a rewrite that gives a rule covering every case a list of objects, or one of several kinds its section names (`Edit at canonical paths only` → `Edit X at canonical paths only`); naming the one thing the line left implied, or the thing its heading names, still passes, and a section is read on its own even when another section has the same heading.
- Heal keeps a rewrite that moves a sentence's scope to its end (`In a monorepo, run X` → `Run X in monorepos`), names a path holding `for` (`docs/for-agents.md`), opens with `For each …`, or changes only the part of a sentence after a prohibition's dash, and reads `in-memory` as one word, not a place.
- Heal's report lists a sentence it made specific once, with every sentence it was split into, so a split no longer reads as a dropped instruction.
- Heal keeps a rewrite that names the referent its section heading gives (`Only use on trusted machines` under `## Remote debugging` → `Only use remote debugging on trusted machines`), and puts back one that turns a forbidden noun into a modifier of a new noun (`Do not edit config` → `Do not edit config files or schemas`), even when the sentence holds a comma elsewhere, or names one of the kinds its heading lists.
- Heal keeps a rewrite that names an object another line of its section mentions only before an `and` that starts a new clause (`Build docs and push`): that `and` does not make the object one kind among several.
- A `(see …)` or `(e.g. …)` aside, an example led by `such as`, `e.g.` or `, like`, and a `(`a`, `b`, `c`)` list of constructs no longer count as a restriction on an instruction; a `You might want to …` line reads as hedged prose, and a packed `Maybe run X, and never skip Y` sentence is read as two instructions.
- In `ails xray`, a details window taller than the screen keeps its title bar and close button on screen wherever the page is scrolled, and its text scrolls inside it.

### Removed

- The `heal_apply` tool is removed; update the reporails plugin to its matching version.

### Internal

- A run's left-out folders and files, and the x-ray view, are read from that run's own config, so an `exclude_dirs` edit shows on the next view of the page.
- An architecture test fails on any core module that imports a driven adapter, in any import form; core declares the port and the command line, MCP server and x-ray page pass the adapter in.
- Caches of the bundled rules and agent settings are bounded, read-only and kept per rules folder, and a rules folder outside the bundle is read fresh on each load.
- CI now runs the model-backed integration tests on a fetched model.
- Which rules a run reports and each rule's line thresholds come from the config the run already read, so a run reads the project config once.
- The Windows check scenarios and the MCP x-ray two-call scenario lose their skip tag. The two-call scenario reads the page while the agent's MCP server still runs, because on Windows the test client ends the server's process tree, the page with it.
- The rewrite-check tests build named constructs, plain text and the rewrite's map as a real run produces them.
- The lint checks read rule pages, fixtures and instruction files through the same file and folder readers as the rest of the run.
- Heal's rewrite check reads each instruction from the map, and a test suite holds rewrites that keep the words but change the meaning.
- One module reads each file's text or bytes for the checks, and each read keeps the decoding it used before.
- Three check scenarios guard linked folders: a `.claude/rules` folder linked to a dotfiles folder stays part of `ails check .claude`, a linked file under a `~/.claude` linked to a dotfiles folder keeps its user-level root, and a `~/.claude` folder keeps its findings when the home folder is reached through a link.
- The map records a place, time or target phrase (`In CI,` before the clause, `in staging` or `for src/` after its object) as the instruction's scope, and heal's rewrite check reads it.
- Discovery reads and lists the project only through the file and folder readers, heal reads and restores files through its own file module, and the rule word lists are written by one module.
- The folder-target check tests run each target from the folder its project roots at, and name a nested root by running from it.

- A check scenario guards the x-ray page checking a rule file written while the page is open.
- Model downloads and the x-ray page's running-page probe go through one HTTP port the command line, MCP server and x-ray page pass in.
