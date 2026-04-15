---
id: CORE:S:0015
slug: skill-entry-point-present
title: "Skill Entry Point Present"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skill}
---
# Skill Entry Point Present

Each skill file must reference or contain a `SKILL.md` entry point. The entry point is the standard discovery mechanism that agents use to find and invoke skills.

## Antipatterns

- Naming the skill entry point `README.md` or `index.md` instead of `SKILL.md`. The check looks for the specific token `SKILL.md` in the file content.
- Creating a skill directory with workflow files but no `SKILL.md` reference. Without the entry point token, the skill is not discoverable.
- Referencing a different filename like `skill.md` (lowercase). The check matches the exact token `SKILL.md`.

## Pass / Fail

### Pass

~~~~markdown
# Check Skill

Entry point: SKILL.md

## Process
1. Run `uv run ails check .`
2. Report results.
~~~~

### Fail

~~~~markdown
# Check Skill

## Process
1. Run the linter.
2. Report results.
~~~~

## Limitations

Uses content analysis on mapped instruction atoms. Results depend on mapper quality and may miss edge cases.
