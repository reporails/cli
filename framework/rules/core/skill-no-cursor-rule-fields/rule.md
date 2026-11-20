---
id: CORE:S:0061
slug: skill-no-cursor-rule-fields
title: Skill No Cursor Rule Fields
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill No Cursor Rule Fields

A skill's frontmatter must not carry `alwaysApply` or `globs`. They are Cursor rule fields, not skill fields, and agents ignore them -- the skill is not always applied and is not limited to those files, even though the file says so.

The check reports a skill file whose frontmatter has a top-level `alwaysApply` or `globs` key.

## Antipatterns

- Copying a Cursor `.mdc` rule header into a skill and keeping `alwaysApply: true`.
- Scoping a skill to files with `globs: "**/*.ts"`.

## Pass / Fail

### Pass

~~~~yaml
---
name: example
description: A skill with only skill fields.
---
~~~~

### Fail

~~~~yaml
---
name: example
description: Has a Cursor field.
alwaysApply: true
---
~~~~

## Limitations

Reads only top-level keys of the frontmatter block; a key nested under another mapping (`metadata:`) is not reported. Does not report other unknown keys.
