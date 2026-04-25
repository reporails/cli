---
id: CLAUDE:S:0012
slug: path-scope-declared
title: Path Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: []
match: {scope: path_scoped}
supersedes: CORE:S:0038
source: https://code.claude.com/docs/en/memory#organize-rules-with-clauderules
---

# Path Scope Declared

Claude Code path-scoped rules must declare a `paths` frontmatter key. The code reads `frontmatter.paths` internally — the `globs` key is not read and rules using it silently load without path scoping. Only `paths` is processed; other frontmatter keys are silently ignored.

## Antipatterns

- **Using `globs` instead of `paths`.** Claude Code reads `frontmatter.paths` internally — the `globs` key is silently ignored and the rule loads without path scoping.
- **Missing frontmatter entirely.** A path-scoped rule file with no `---` block. The file loads for all contexts instead of being scoped to specific files.
- **Using `description` or `scope` as proxy.** Adding metadata fields like `description: "Python rules"` instead of the actual `paths` key. Only `paths` is processed for scoping.

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

## Limitations

Does not verify that matched files are the ones the author intended — only that the glob resolves to at least one file. Cannot detect overly broad patterns like `paths: "**/*"` that effectively disable scoping.
