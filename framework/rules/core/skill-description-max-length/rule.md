---
id: CORE:S:0060
slug: skill-description-max-length
title: Skill Description Max Length
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill Description Max Length

A skill's `description` must be at most 1,024 characters. Agents that enforce the open skill schema cut a longer description short or refuse the skill, so the text that tells the agent when to use the skill is lost.

The check reports a skill file whose frontmatter `description` is longer than 1,024 characters, whether it is written on one line or continued over indented lines.

## Antipatterns

- Pasting the whole workflow and every example into `description` instead of the markdown body.
- A description that lists every trigger phrase in full sentences.

## Pass / Fail

### Pass

~~~~yaml
---
name: example
description: Short description. Use when needed.
---
~~~~

### Fail

~~~~yaml
---
name: example
description: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
---
~~~~

## Limitations

Counts the characters of the parsed `description` value, so a folded or literal block is counted as its text with no indentation, line endings or trailing comment. A frontmatter block that does not parse as YAML is left to `frontmatter_valid_yaml`. The 1,024 limit is the open-standard cap; an agent with a lower cap is not checked. Presence and quality of the description are covered by `skill-description-present`.
