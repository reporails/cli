---
id: CLAUDE:S:0002
slug: skill-name-matches-directory
title: Skill Name Matches Directory
category: structure
type: deterministic
severity: medium
backed_by: []
match: {type: skill}
source: https://code.claude.com/docs/en/skills
---

# Skill Name Matches Directory

The `name` field in `SKILL.md` YAML frontmatter MUST match the containing directory name in kebab-case. Claude Code uses the directory name for skill discovery and the frontmatter name for display — a mismatch causes the skill to be invocable under one name but displayed under another.

## Antipatterns

- **CamelCase name.** Using `commitHelper` instead of `commit-helper`. Claude Code expects kebab-case in the `name` field to match the directory naming convention.
- **Name/directory mismatch.** Directory is `review-pr/` but frontmatter says `name: pr-review`. The skill is invocable as `/review-pr` (from directory) but displayed as `pr-review` (from frontmatter).
- **Missing name field.** Omitting the `name` field entirely from frontmatter. Claude Code falls back to the directory name but the skill appears without a display name in listings.

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

Checks that a kebab-case `name:` field exists in frontmatter. Does not verify the name matches the exact directory name — only that the format is valid kebab-case.

