---
id: CORE:S:0038
slug: path-scope-declared
title: Path Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: [awesome-copilot-meta-instructions, fowler-context-engineering-agents,
  rules-directory-mechanics]
match: {scope: path_scoped}
---

# Path Scope Declared

Path-scoped instruction files must declare which paths they apply to via a frontmatter key. Without a scope declaration, the file loads for all contexts instead of being scoped to specific files.

Each agent uses a different frontmatter key for path scoping:
- Claude: `paths`
- Cursor: `globs`
- Copilot: `applyTo`

## Antipatterns

- **Scoped file without frontmatter scope key.** Loads for all contexts instead of being scoped, wasting context tokens.
- **Using the wrong key for the agent.** Each agent checks a specific key — the wrong key is silently ignored.
- **Empty frontmatter block.** A file with `---` / `---` but no keys still fails — the scope key must be present.

## Pass / Fail

### Pass

~~~~markdown
---
paths: src/**/*.py
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

Core check verifies frontmatter is present. Agent-level overrides check the specific scope key (e.g., `paths` for Claude, `globs` for Cursor, `applyTo` for Copilot).
