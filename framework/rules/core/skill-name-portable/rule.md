---
id: CORE:S:0059
slug: skill-name-portable
title: Skill Name Portable
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill Name Portable

A skill's `name` must be at most 64 characters and must not contain the reserved words `anthropic` or `claude`. Agents that enforce the open skill schema refuse to load a skill whose name breaks either limit, so the skill never appears.

The check reports a skill file whose frontmatter `name` is longer than 64 characters, or contains `anthropic` or `claude` in any letter case.

## Antipatterns

- A name such as `claude-code-helper` -- it holds the reserved word `claude`.
- A name written as a full sentence that runs past 64 characters.

## Pass / Fail

### Pass

~~~~yaml
---
name: commit-helper
description: Create a commit. Use when asked to commit.
---
~~~~

### Fail

~~~~yaml
---
name: claude-helper
description: Uses a reserved word.
---
~~~~

## Limitations

Measures the parsed `name` value, so a quoted name, a trailing comment and a name written over several lines are read as the agent reads them. A frontmatter block that does not parse as YAML is left to `frontmatter_valid_yaml`. Does not check the name's character set or its match with the directory (`skill-name-matches-directory` does).
