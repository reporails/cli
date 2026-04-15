---
id: CLAUDE:S:0002
slug: the-name-field-in-skill-md-frontmatter-matches-the-containin
title: The Name Field In Skill.Md Frontmatter Matches The Containing Directory 
  Name (Kebab Case)
category: structure
type: deterministic
severity: medium
backed_by:
- building-skills-for-claude
match: {type: skill}
---

# Skill Name Matches Directory

The `name` field in `SKILL.md` YAML frontmatter MUST match the containing directory name in kebab-case. Claude Code uses the directory name for skill discovery and the frontmatter name for display — a mismatch causes the skill to be invocable under one name but displayed under another.

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

