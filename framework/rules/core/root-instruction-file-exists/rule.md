---
id: CORE:S:0007
slug: root-instruction-file-exists
title: "Root Instruction File Exists"
category: structure
type: mechanical
severity: critical
backed_by: []
match: {type: main}
---

# Root Instruction File Exists

A root instruction file must exist at the project root. This is the primary entry point for any AI coding agent.

## Antipatterns

- **Placing the instruction file in a subdirectory.** A `CLAUDE.md` inside `docs/` or `.claude/` is not at the project root. The check verifies that a main instruction file exists at the root level.
- **Using a non-standard filename.** A file named `instructions.md` or `AI-RULES.md` at the root will not be recognized as the main instruction file. The file must match the expected root filename pattern for the agent.
- **Empty project with no instruction file.** A repository that has source code but no root instruction file fails this check. Even a minimal instruction file satisfies the requirement.

## Pass / Fail

### Pass

~~~~markdown
project/
  CLAUDE.md
  src/
  tests/
~~~~

### Fail

~~~~markdown
project/
  src/
  tests/
  docs/CLAUDE.md
~~~~

## Limitations

Checks that the expected file exists. Does not evaluate file contents.
