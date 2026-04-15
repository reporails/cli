---
id: CORE:S:0025
slug: rules-directory-structure
title: "Rules Directory Structure"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: scoped_rule}
---

# Rules Directory Structure

When scoped rule files exist, they must reside in the expected directory for the agent (e.g., `.claude/rules/`). This ensures the agent discovers and loads rules correctly at session start.

## Antipatterns

- **Scoped rules placed at project root.** Rule files like `testing-design.md` dropped into the project root instead of `.claude/rules/` will not be discovered by the agent's rule loader.
- **Incorrect directory name.** Placing rules in `.claude/rule/` (singular) or `.claude/instructions/` instead of `.claude/rules/` breaks the expected directory structure.
- **Rules directory exists but is empty.** The check verifies that at least one scoped rule file exists. An empty `.claude/rules/` directory with no `.md` files inside passes `directory_exists` but provides no scoped guidance.

## Pass / Fail

### Pass

~~~~markdown
project/
  .claude/rules/
    testing-design.md
    sensitive-files.md
  CLAUDE.md
~~~~

### Fail

~~~~markdown
project/
  testing-design.md
  sensitive-files.md
  CLAUDE.md
~~~~

## Limitations

Checks that the rules directory exists with the expected structure. Does not evaluate individual rule file quality.
