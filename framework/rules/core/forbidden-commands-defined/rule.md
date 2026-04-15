---
id: CORE:G:0004
slug: forbidden-commands-defined
title: "Forbidden Commands Defined"
category: governance
type: mechanical
severity: medium
backed_by: []
match: {type: main}
---
# Forbidden Commands Defined

The main instruction file must contain at least one constraint atom that prohibits specific commands or actions. Listing forbidden operations prevents the agent from executing destructive commands like `git push --force`, `rm -rf`, or database mutations without explicit user approval.

## Antipatterns

- **Describing dangerous commands without prohibiting them** like "The `git reset --hard` command discards changes" — description is not a constraint, the check requires imperative prohibition.
- **Prohibitions only in scoped rule files** like constraints in `.claude/rules/sensitive-files.md` but none in `CLAUDE.md` — the check targets `type: main`, so the main file must contain its own constraint atoms.
- **Generic warnings** like "Be careful with destructive operations" — vague cautions do not produce constraint atoms.

## Pass / Fail

### Pass

~~~~markdown
# Constraints
NEVER run `git push --force` on `main`.
*Do NOT modify `.env` or `credentials*` files.*
~~~~

### Fail

~~~~markdown
# Commands
Use `git push` to publish changes.
Use `git reset` to undo changes.
~~~~

## Limitations

Uses content analysis on mapped instruction atoms. Results depend on mapper quality and may miss edge cases.
