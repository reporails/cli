---
id: CLAUDE:S:0001
slug: skill-folder-does-not-contain-readme-md-all-documentation-go
title: Skill Folder Does Not Contain Readme.Md — All Documentation Goes In 
  Skill.Md
category: structure
type: mechanical
severity: high
backed_by:
- building-skills-for-claude
match: {type: skill}
---

# Skill Folder — No README.md

Skill directories under `.claude/skills/` MUST NOT contain a `README.md` file. All skill documentation belongs in `SKILL.md` — Claude Code discovers and loads `SKILL.md` as the skill entry point. A separate `README.md` splits documentation across two files and the extra file is never loaded.

## Pass / Fail

### Pass

```
.claude/skills/commit/
├── SKILL.md      # All documentation here
└── helpers.py
```

### Fail

```
.claude/skills/commit/
├── SKILL.md
├── README.md     # Redundant — not loaded by Claude Code
└── helpers.py
```

## Limitations

Only checks for `README.md` presence in skill directories. Does not detect other redundant documentation files.

