---
id: CLAUDE:S:0003
slug: skill-yaml-frontmatter-description-field-is-under-1024-chara
title: Skill Yaml Frontmatter Description Field Is Under 1024 Characters And 
  Contains No Xml Angle Brackets
category: structure
type: mechanical
severity: high
backed_by:
- building-skills-for-claude
match: {type: skill}
---

# Skill Description Length Limit

The `description` field in `SKILL.md` YAML frontmatter MUST be under 1024 characters. Claude Code uses this field for skill discovery — long descriptions waste context tokens and may be truncated. Keep descriptions concise: state what the skill does and when to invoke it.

## Pass / Fail

### Pass

```yaml
---
name: commit
description: "Create a git commit with a conventional message format. Use when the user asks to commit changes."
---
```

### Fail

```yaml
---
name: commit
description: "This skill handles creating git commits. It supports conventional commit format, multi-line messages, co-authored-by trailers, GPG signing, and can also amend previous commits. The skill reads the git diff, analyzes changes across all modified files, determines the appropriate commit type (feat, fix, chore, docs, refactor, test, style, perf, ci, build), generates a summary of changes... [800+ more characters]"
---
```

## Limitations

Checks total file size as a proxy for description length. Does not parse the YAML frontmatter to measure the description field independently.

