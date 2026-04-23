---
id: CLAUDE:S:0012
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

Claude Code path-scoped rules must declare a `paths` frontmatter key. The code reads `frontmatter.paths` internally — the `globs` key is not read and rules using it silently load without path scoping. Only `paths` is processed; other frontmatter keys are silently ignored.

## Formats

Single path:

```yaml
---
paths: src/**/*.py
---
```

Multiple paths (YAML list):

```yaml
---
paths:
  - "src/**/*.{ts,tsx}"
  - "lib/**/*.ts"
  - "tests/**/*.test.ts"
---
```

All value formats work as of v2.1.104: unquoted string, YAML list, inline YAML array, quoted string.

## Pass / Fail

### Pass

~~~~markdown
---
paths:
  - "src/**/*.py"
---
# Testing Design

Tests exist to catch bugs, not to confirm the implementation works.
~~~~

### Fail

~~~~markdown
---
globs: src/**/*.py
description: Python testing rules
---
# Testing Design

Tests exist to catch bugs, not to confirm the implementation works.
~~~~
