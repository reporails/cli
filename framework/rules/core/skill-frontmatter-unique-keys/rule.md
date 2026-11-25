---
id: CORE:S:0062
slug: skill-frontmatter-unique-keys
title: Skill Frontmatter Unique Keys
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill Frontmatter Unique Keys

Each top-level key in a skill's frontmatter must appear once. Codex, Copilot CLI and OpenCode drop a skill whose frontmatter repeats a key, so the skill never loads there even though other agents read it.

The check reports a skill file whose frontmatter block has the same top-level key on two lines.

## Antipatterns

- Adding a second `description:` line while editing and leaving the first.
- Merging two skills and keeping both `name:` lines.

## Pass / Fail

### Pass

~~~~yaml
---
name: example
description: Every key once.
---
~~~~

### Fail

~~~~yaml
---
name: example
description: First.
description: Second.
---
~~~~

## Limitations

Compares plain top-level keys (letters, digits, `_`, `-`) written at the start of a line; quoted keys and keys under a nested mapping are not compared. Reads only the frontmatter block.
