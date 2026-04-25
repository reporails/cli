---
id: CLAUDE:S:0003
slug: skill-description-length
title: Skill Description Length
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skill}
source: https://code.claude.com/docs/en/skills
---

# Skill Description Length

The `description` field in `SKILL.md` YAML frontmatter MUST be present and concise. Claude Code caps the combined `description` + `when_to_use` text at 1,536 characters in the skill listing. Long descriptions waste context tokens and get truncated. Front-load the key use case.

## Antipatterns

- **Embedding full documentation in description.** Putting the entire skill workflow, all edge cases, and example invocations into the `description` field instead of the markdown body. The description is for discovery, not documentation.
- **XML/HTML tags in description.** Including `<example>`, `<step>`, or other angle-bracket markup in the description field. Claude Code may interpret these as system tags rather than content.
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

Checks that the `description` field exists in frontmatter. Does not verify the field length against the 1,536-character cap — precise length validation requires YAML parsing (not yet implemented).

