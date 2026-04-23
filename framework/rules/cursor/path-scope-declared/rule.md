---
id: CURSOR:S:0001
slug: path-scope-declared
title: "Path Scope Declared"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {scope: path_scoped}
supersedes: CORE:S:0038
---

# Path Scope Declared

Cursor path-scoped rules must declare a `globs` frontmatter key. Rules without `globs` and without `alwaysApply: true` are manual-only (loaded via @-mention, not automatically).

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
