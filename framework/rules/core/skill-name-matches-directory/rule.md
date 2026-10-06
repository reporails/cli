---
id: CORE:S:0036
slug: skill-name-matches-directory
title: Skill Name Matches Directory
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://agentskills.io/specification
---

# Skill Name Matches Directory

The `name` field in `SKILL.md` YAML frontmatter MUST match the containing directory name in kebab-case. Skill loaders use the directory name for discovery and the frontmatter name for display — a mismatch causes the skill to be invocable under one name but displayed under another.

## Antipatterns

- **CamelCase name.** Using `commitHelper` instead of `commit-helper`. Skill loaders expect kebab-case in the `name` field to match the directory naming convention.
- **Name/directory mismatch.** Directory is `review-pr/` but frontmatter says `name: pr-review`. The skill is invocable as `/review-pr` (from directory) but displayed as `pr-review` (from frontmatter).
- **Directory renamed without updating the field.** Moving a skill from `pr-review/` to `review-pr/` but leaving `name: pr-review` in frontmatter. The stale name no longer equals the directory and is flagged.

## Pass / Fail

### Pass

```
.claude/skills/commit-helper/SKILL.md
---
name: commit-helper
---
```

### Fail

```
.claude/skills/commit-helper/SKILL.md
---
name: commitHelper
---
```

## Limitations

Compares the frontmatter `name` value against the containing directory name and flags any mismatch. A `name` that is absent (or not a string) is not flagged — loaders fall back to the directory name, so the default trivially matches. The check tests equality with the directory, not kebab-case formatting on its own: a name equal to a non-kebab directory passes, and a kebab-case name that differs from the directory still fails.

