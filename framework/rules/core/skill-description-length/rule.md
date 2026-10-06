---
id: CORE:S:0040
slug: skill-description-length
title: Skill Description Present
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://agentskills.io/specification
---

# Skill Description Present

The `description` field in `SKILL.md` YAML frontmatter MUST be present and non-empty. The description is what a host agent reads to decide whether to load a skill — it is the skill's discovery surface. A `SKILL.md` with no description (or an empty one) is effectively invisible: the agent cannot tell when the skill applies, so it is never invoked. Front-load the key use case in one or two sentences and keep it concise.

## Antipatterns

- **No description field.** Frontmatter that declares `name` but omits `description` entirely. The skill has no discovery text for the host agent to match against.
- **Empty description.** A `description:` key present but with no value (or only whitespace). Same effect as omitting it — nothing for the agent to read.
- **Description nested under another key.** Putting `description:` under a `metadata:` mapping instead of at the frontmatter's top level. No skill loader reads it there.
- **Embedding full documentation in the description.** Putting the entire skill workflow, all edge cases, and example invocations into the `description` field instead of the markdown body. The description is for discovery, not documentation.

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
---
```

## Limitations

Checks only that a non-empty `description` value is declared at the top level of the `SKILL.md` YAML frontmatter block, either on the same line as the colon or as a YAML plain-scalar / block-scalar (`|`, `>`) value continued on the following indented line. The check reads only the block between the opening `---` and the first closing `---` — or end of file, when the frontmatter is never closed; an unterminated block still counts as present once the key is found, and this check does not itself flag the missing closing fence — and requires the key at column 0 — a `description` indented under another mapping (`metadata:`) and a `description` shown in a fenced example in the body neither live in that block nor at its top level, so neither satisfies the requirement. The key search is bounded to the first 200 lines after the opening fence; a `description` declared later in an unusually long frontmatter block is not found. Does not measure the field's length against the open-standard 1024-character cap or any agent-specific cap, and does not evaluate the quality or relevance of the text.
