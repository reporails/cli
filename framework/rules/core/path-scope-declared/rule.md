---
id: CORE:S:0038
slug: path-scope-declared
title: "Path Scope Declared"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {scope: path_scoped}
---

# Path Scope Declared

Path-scoped rules must declare which paths they apply to. Without a scope declaration, the rule's applicability is ambiguous.

## Antipatterns

- **Scoped rule file without `globs` frontmatter.** A rule in `.claude/rules/` that omits the `globs` key has no declared scope. The agent cannot determine which files the rule applies to, making it effectively invisible to path-based discovery.
- **Using `paths` instead of `globs`.** The check looks for the `globs` frontmatter key specifically. A rule that declares its scope under a different key name (e.g., `paths`, `applies_to`) will fail this check.
- **Empty frontmatter block.** A rule file with `---` / `---` but no keys inside still fails -- the `globs` key must be present, not just the frontmatter block.

## Pass / Fail

### Pass

~~~~markdown
---
globs: src/**/*.py
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

Checks that the `globs` frontmatter key is present. Does not validate whether the glob patterns are correct or match actual file paths.
