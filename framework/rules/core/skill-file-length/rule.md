---
id: CORE:S:0031
slug: skill-file-length
title: "Skill File Length"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skill}
source: https://agentskills.io/specification
---

# Skill File Length

Skill entry point files must stay under 500 lines. Agents load the full SKILL.md body into context on activation. Long skill files consume context budget and displace conversation history. Move detailed reference material to separate files in the skill directory.

## Antipatterns

- **Embedding reference docs in SKILL.md.** Pasting API documentation, schema definitions, or long examples directly into the skill file instead of referencing separate files.
- **Multiple workflows in one file.** Combining check, fix, and explain workflows in a single SKILL.md. Split into separate workflow files and load on demand.
- **Inline scripts.** Including long shell or Python scripts inline when they should be in `scripts/`.

## Pass / Fail

### Pass

A SKILL.md under 500 lines with references to supporting files:

```markdown
---
name: my-skill
description: Does something useful
---

# My Skill

Instructions here. See [reference.md](reference.md) for details.
```

### Fail

A SKILL.md over 500 lines with everything inline.

## Limitations

Checks line count of the skill entry point file. Does not check supporting files in the skill directory. The 500-line limit follows both the Claude Code recommendation and the Agent Skills specification.
