---
id: CORE:C:0056
slug: subagent-tools-field-canonical
title: Subagent Tools Field Canonical
category: coherence
type: deterministic
severity: medium
requires_capability: agents
backed_by: []
match: {type: agents, format: [frontmatter, freeform]}
source: https://code.claude.com/docs/en/sub-agents
---

# Subagent Tools Field Canonical

A subagent definition restricts its tools with the `tools` field (an allow-list) or the `disallowedTools` field (a deny-list). It does not use `allowed-tools` — that is the skill (`SKILL.md`) field. A subagent frontmatter declaring `allowed-tools:` (or the non-existent `allowedTools:`) is silently ignored by the harness: the intended restriction never applies and the subagent inherits every tool. Name the restriction with `tools:` so the allow-list actually binds.

## Antipatterns

- **Porting the skill field into an agent.** Copying `allowed-tools: Read, Grep` from a `SKILL.md` into a `.claude/agents/*.md` — the subagent contract reads `tools`, so the copied field does nothing and the agent runs unrestricted.
- **Guessing the camelCase form.** Writing `allowedTools:` by analogy with `disallowedTools:` — there is no `allowedTools` field; the allow-list is `tools`.

## Pass / Fail

### Pass

```yaml
---
name: reviewer
description: Use when reviewing a diff.
tools: Read, Grep, Glob
disallowedTools: Write, Edit
---
```

### Fail

```yaml
---
name: reviewer
description: Use when reviewing a diff.
allowed-tools: Read, Grep, Glob
---
```

## Limitations

Flags a `allowed-tools` / `allowedTools` key in subagent frontmatter. Does not validate that the tool names listed in a correct `tools` field resolve to real tools.
