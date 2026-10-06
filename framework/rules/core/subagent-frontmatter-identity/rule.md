---
id: CORE:S:0057
slug: subagent-frontmatter-identity
title: Subagent Frontmatter Identity
category: structure
type: deterministic
severity: medium
requires_capability: agents
backed_by: []
match: {type: agents, format: [frontmatter, freeform]}
source: https://code.claude.com/docs/en/sub-agents
---

# Subagent Frontmatter Identity

A subagent definition (`.claude/agents/<name>.md`) must declare both `name` and `description` in its YAML frontmatter. The Claude Code subagent contract lists both as required fields: `name` is the unique identifier the dispatch handle and hooks (`agent_type`) resolve against, and `description` is the text the model reads to decide when to delegate. A subagent missing `description` is never auto-selected for a task; one missing `name` cannot be addressed deterministically. Declare both so the harness loads and routes the subagent instead of silently ignoring it.

## Antipatterns

- **Body-only agent file.** Writing the agent's system prompt as markdown with no frontmatter block at all — the harness reads `name` / `description` from frontmatter, so a body-only file loads without a routing handle.
- **Description omitted.** Declaring `name` but no `description`, on the assumption the body explains the role — the model selects a subagent from its `description`, so an absent one never fires.
- **Identity nested under another key.** Declaring `author:` with `name:` and `description:` indented beneath it — the harness reads the top-level keys, so a nested pair leaves the subagent with no routing handle.
- **Identity shown only as a body example.** Leaving the frontmatter empty and writing the intended `name` / `description` inside a fenced `yaml` block in the body — the harness never parses the body, so the fields do not exist.
- **Prose description of the file, not the delegation trigger.** A `description` that narrates what the file is (`This is the reviewer agent`) rather than when to delegate to it (`Use when reviewing a diff for correctness bugs`).

## Pass / Fail

### Pass

```yaml
---
name: code-reviewer
description: Use when reviewing a diff for correctness bugs and security issues.
tools: Read, Grep, Glob
---
```

### Fail

```yaml
---
tools: Read, Grep, Glob
---
You are a code reviewer.
```

## Limitations

Checks that `name` and `description` are declared at the top level of the YAML frontmatter block with a non-empty value, either on the same line as the colon or as a YAML plain-scalar / block-scalar (`|`, `>`) value continued on the following indented line. The check reads only the block between the opening `---` and the first closing `---` — or end of file, when the frontmatter is never closed; an unterminated block still counts as present once the key is found, and this check does not itself flag the missing closing fence — and requires the key at column 0 — a key indented under another mapping (`author.name`) and a key shown in a fenced example in the body are both outside the block or outside the top level, so neither satisfies the requirement. The key search is bounded to the first 200 lines after the opening fence; a key declared later in an unusually long frontmatter block is not found. Does not validate the `name` value against the lowercase-hyphen identifier rule, nor grade the `description` for delegation-trigger quality.
