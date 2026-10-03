---
id: CORE:G:0004
slug: forbidden-commands-defined
title: Forbidden Commands Defined
category: governance
type: mechanical
enforcement_required: true
enforcement_mechanism: permission
severity: medium
depends_on: [CORE:C:0019]
backed_by: [claude-code-issue-13579, spec-writing-for-agents]
match: {type: main}
---
# Forbidden Commands Defined

The main instruction file must contain at least one prohibition that rules out an abstract category of dangerous operation. Bounding destructive operations as a category prevents the agent from force-pushing, deleting files, or mutating the database without explicit user approval.

## Antipatterns

- **Describing dangerous commands without prohibiting them** like "The `git reset --hard` command discards changes" — description is not a prohibition, the check requires an imperative prohibition.
- **Prohibitions only in scoped rule files** like constraints in `.claude/rules/sensitive-files.md` but none in `CLAUDE.md` — the check targets `type: main`, so the main file must contain its own prohibitions.
- **Generic warnings** like "Be careful with destructive operations" — vague cautions do not read as a prohibition.

## Pass / Fail

### Pass

~~~~markdown
# Constraints
Never force-push to a protected branch.
*Do not modify environment or credential files.*
~~~~

### Fail

~~~~markdown
# Commands
Use `git push` to publish changes.
Use `git reset` to undo changes.
~~~~

## Limitations

Checks for at least one prohibition defining forbidden operations. Does not verify the forbidden list covers the project's actual dangerous commands.
