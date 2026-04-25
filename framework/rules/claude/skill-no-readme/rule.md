---
id: CLAUDE:S:0001
slug: skill-no-readme
title: Skill No README
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skill}
source: https://code.claude.com/docs/en/skills
---

# Skill Folder — No README.md

Skill directories under `.claude/skills/` MUST NOT contain a `README.md` file. All skill documentation belongs in `SKILL.md` — Claude Code discovers and loads `SKILL.md` as the skill entry point. A separate `README.md` splits documentation across two files and the extra file is never loaded.

## Antipatterns

- **Splitting documentation across files.** Creating both `SKILL.md` and `README.md` in the same skill directory. Claude Code only loads `SKILL.md` — content in `README.md` is never seen by the agent.
- **README.md as primary docs.** Writing the skill documentation in `README.md` out of habit (standard GitHub convention) and leaving `SKILL.md` as a stub. The agent gets the stub, not the documentation.
- **Generated README.** Letting a tool auto-generate a `README.md` in every directory including skill directories. The extra file wastes disk space and creates confusion about which file is authoritative.

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

