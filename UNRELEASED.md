# Unreleased

### Added

- Config: `heal_exclude` in `.ails/config.yml` (or `.ails/config.local.yml`) keeps heal off the files you name, as globs relative to the project root. They are still checked and scored, their findings and scores do not change, and their findings are listed with the reason `excluded` instead of being offered for a rewrite. `ails check --heal` also leaves these files unchanged. See "Keeping heal off a file" in the configuration guide.
- MCP: when you check a file that was briefed for a rewrite, the `preservation` block reports `introduced`, the number of findings the file has beyond those it had when it was briefed.
- MCP: `validate` names the hooks in your project and user settings that can block or change heal's file reads and writes.

### Changed

- Check: a heading that labels a category and has a sibling label at the same level (for example `## Keep — …` and `## Partial — …`) is no longer reported as an instruction in a heading (CORE:S:0039), so files with such headings can score higher. A heading whose leading word gives an order (`Always`, `Never`) or whose text after the dash gives an instruction is still reported.
- Check: the fix text for a sentence that holds several instructions (CORE:C:0058) now says each sentence must stand on its own after the split: repeat the subject or object they share, keep a directive with the bound that limits it, and keep a lead-in with every item it introduces.
- MCP: on a Pro account, `validate` returns a short text view (status, surfaces, the locations to rewrite, what stays listed and the rewrite check) instead of the full JSON; pass `full=true` for the JSON.
- Docs: the tier pages describe Pro as what the server works out for your project — which findings to fix first and which to leave alone, the exact line of each cross-file repetition and overlap, and a re-check of each rewritten file.
- MCP: a `validate` call narrowed with `targets` stays small: it carries its locations' findings while they fit and otherwise points to the rewrite brief.
- MCP: the rewrite brief each remedy agent fetches is smaller; the guide to writing an ideal instruction now comes with the remedy agent itself, so use the reporails plugin release that matches this cli.

### Fixed

- Heal: a rewrite that ties a rule about a whole class to one named tool ("every gate" becoming "every `X` gate") is now caught and put back, including when another sentence on the same line already names the tool. A rewrite that adds a place or scope to a rule ("define what to build" becoming "define what to build in that spec") is put back even when the line already used those words elsewhere, for example as the thing another instruction produces. A place that only names where a tool or file lives ("at `vision.md`") is listed, not put back.
- Heal: a sentence split that leaves a fragment behind (a lead-in holding only the first item of its list, or a dangling "— ask.") is now caught and put back. This includes a lead-in reworded to keep only the first item of its list ("You are the author: you read the request, classify it, and write the entry" becoming "You are the author who reads the request." followed by bare commands). A split that ends a sentence partway through its list, keeping the first few items and moving the rest to a new sentence, is put back too. A split that repeats the lead-in before each item, or gives each item its own sentence, is kept, a colon or dash inside a code span or a step that starts with "then" is not mistaken for a list, and a sentence the rewrite left unchanged is never reported as a fragment.
- Heal: a rewrite that adds a named tool or file to a rule is now listed in the report, so you can undo it.
- Check: when your project is a git repository, a separate repository inside it, such as a repository you cloned into the project or a git worktree under `.claude/worktrees/`, is no longer checked as part of your project, so its rules, skills and agents no longer add to your findings and score. Check it on its own with `ails check <folder>`. Git submodules, and skills or agents you cloned into your own `.claude/skills/` or `.claude/agents/` folder, are still checked.
- Check: an `@` import that does not resolve is reported on the file that holds it, at the import's line, instead of on your main instruction file, and a relative import is looked up from the folder of the file that holds it. Before, a correct relative import in a nested `CLAUDE.md` could be reported as broken.
- Docs: the configuration guide's list of folders that are always skipped no longer includes `.vscode`, which is checked (GitHub Copilot keeps its settings there).
- MCP: the `compression` line of a `validate` reply counts each finding once, so the findings it reports are the per-file and cross-file findings, split into those that move your score and the cosmetic rest.
- Docs: the tier table lists the remedy among the Pro cross-file details.

### Removed

### Internal
