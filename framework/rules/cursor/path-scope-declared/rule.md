---
id: CURSOR:S:0001
slug: path-scope-declared
title: Path Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: []
match: {scope: path_scoped}
supersedes: CORE:S:0038
source: https://docs.cursor.com/context/rules
---

# Path Scope Declared

Cursor path-scoped rules must declare a `globs` frontmatter key. Rules without `globs` and without `alwaysApply: true` are manual-only (loaded via @-mention, not automatically).

## Antipatterns

- **Using `paths` instead of `globs`.** Cursor reads `frontmatter.globs` for scoping — using `paths` (Claude Code's key) has no effect and the rule becomes manual-only.
- **Missing `globs` and `alwaysApply`.** A rule file with neither `globs` nor `alwaysApply: true` is only loaded when explicitly mentioned via `@`. It never fires automatically.
- **Frontmatter without scope key.** Adding metadata like `description: "Testing rules"` but omitting both `globs` and `alwaysApply`. Cursor ignores unrecognized frontmatter keys.

## Pass / Fail

### Pass

~~~~markdown
---
globs: ["src/**/*.py"]
---
# Testing Design

Tests exist to catch bugs, not to confirm the implementation works.
~~~~

### Fail

~~~~markdown
---
description: Rules for testing files
---
# Testing Design

Tests exist to catch bugs, not to confirm the implementation works.
~~~~

## Limitations

Does not check for `alwaysApply` interaction — a rule with both `globs` and `alwaysApply: true` may behave unexpectedly. Cannot detect overly broad globs like `**/*` that effectively disable scoping.
