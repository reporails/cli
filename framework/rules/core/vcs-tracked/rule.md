---
id: CORE:G:0001
slug: vcs-tracked
title: "Vcs Tracked"
category: governance
type: mechanical
severity: high
backed_by: []
match: {format: [freeform, frontmatter, schema_validated]}
---

# Vcs Tracked

All instruction files must be tracked in git. Untracked instruction files create divergence between collaborators -- each developer's agent sees different instructions.

## Antipatterns

- Adding an instruction file but forgetting to `git add` it. The file works locally but is invisible to other contributors.
- Adding instruction file paths to `.gitignore` (e.g., ignoring all `.md` files in `.claude/`). Instruction files must be committed, not ignored.
- Creating instruction files in directories outside the repository root. Files outside the repo boundary cannot be git-tracked.

## Pass / Fail

### Pass

~~~~markdown
$ git ls-files .claude/rules/testing.md
.claude/rules/testing.md
(file is tracked)
~~~~

### Fail

~~~~markdown
$ git ls-files .claude/rules/testing.md
(no output -- file is not tracked)
~~~~

## Limitations

Structural check with limited semantic understanding.
