---
id: CORE:S:0064
slug: skill-frontmatter-string-keys
title: Skill Frontmatter String Keys
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill Frontmatter String Keys

Top-level frontmatter keys in a skill must read as text. A bare `yes`, `no`, `on`, `off`, `true`, `false`, `null`, a number or a date is read by YAML as a boolean, null, number or date, so agents look for a field that is never found under that name.

The check reports a skill file whose frontmatter has a top-level key that is a bare `yes`, `no`, `on`, `off`, `true`, `false`, `null`, `~`, a number or a date (`2026-01-31`).

## Antipatterns

- A key written as `no:` or `on:` -- YAML turns it into `false` or `true`.
- A numeric key such as `1:`.

## Pass / Fail

### Pass

~~~~yaml
---
name: example
description: Every key is text.
---
~~~~

### Fail

~~~~yaml
---
name: example
description: Has a boolean key.
yes: maybe
---
~~~~

## Limitations

Reads plain top-level keys only; a key in quotes (`"no":`) is text and is not reported, nor is a key nested under another mapping. Values are not checked.
