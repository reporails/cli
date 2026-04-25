---
id: CORE:S:0011
slug: child-nested-instructions
title: Child Nested Instructions
category: structure
type: deterministic
severity: medium
backed_by: [openai-community-agents-md-optimization, rules-directory-mechanics, sewell-agents-md-tips]
match: {cardinality: hierarchical}
---
# Child Nested Instructions

Child instruction files must extend their parent's scope without contradicting it. Contradictions between levels create confusion.

## Antipatterns

- Writing "ignore parent instructions" in a child file to start fresh. The check detects "ignore parent" and "ignore all" as override language. Child files should extend, not replace.
- Using "override everything above" to reset inherited directives. The check flags "override everything" and "override all" as blanket overrides.
- Phrasing a narrow exception as a broad override ("ignore all previous rules, then re-add the ones we want"). Even if the intent is selective, the language triggers the blanket-override pattern.

## Pass / Fail

### Pass

~~~~markdown
# Frontend Rules

Use React 18 for components.
Prefer CSS modules over inline styles.
~~~~

### Fail

~~~~markdown
# Frontend Rules

Ignore parent instructions.
Override everything from the root file.
~~~~

## Limitations

Detects parent-override language (`ignore parent`, `override everything`). Does not evaluate whether the override scope is appropriate.
