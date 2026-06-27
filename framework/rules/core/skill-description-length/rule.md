---
id: CORE:S:0040
slug: skill-description-length
title: Skill Description Length
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skill}
source: https://agentskills.io/specification
---

# Skill Description Length

The `description` field in `SKILL.md` YAML frontmatter MUST be present and concise. The Agent Skills open standard at agentskills.io caps the field at **1024 characters**, and GitHub Copilot enforces the same 1024-character cap explicitly. Claude Code caps the combined `description` + `when_to_use` text at **1,536 characters** in the skill listing. Codex bounds the entire skill list (not the individual description) at roughly 2% of the model context window or 8000 characters. Cursor and Antigravity do not document a hard cap but follow the open standard. A description that respects 1024 characters is portable across every agent; long descriptions waste context tokens and risk truncation in the agents that enforce the tighter cap. Front-load the key use case.

## Antipatterns

- **Embedding full documentation in description.** Putting the entire skill workflow, all edge cases, and example invocations into the `description` field instead of the markdown body. The description is for discovery, not documentation.
- **XML/HTML tags in description.** Including `<example>`, `<step>`, or other angle-bracket markup in the description field. The host agent may interpret these as system tags rather than content.
- **Copy-pasting the skill body.** Duplicating the markdown body into the description field. The description should be a 1-2 sentence summary, not a repeat of the full content.

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

Checks that the `description` field exists in frontmatter. Does not verify the field length against the open-standard 1024-character cap or any agent-specific cap — precise length validation requires YAML parsing (not yet implemented).

