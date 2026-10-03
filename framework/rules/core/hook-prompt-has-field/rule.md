---
id: CORE:S:0030
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
requires_capability: hooks
---

# Hook Prompt Has Field

A hook handler declared with `"type": "prompt"` or `"type": "agent"` must carry its own non-empty `"prompt"` field. A config with no prompt- or agent-typed handler at all draws no finding from this check — there is nothing for it to require a prompt on.

## Antipatterns

- **Missing prompt field.** Defining `"type": "prompt"` without a `"prompt"` key in the same handler object.
- **Command field instead of prompt.** Setting `"type": "prompt"` with a `"command"` field — the handler expects `"prompt"` for its instruction text, not `"command"`.
- **Agent handler missing prompt.** Defining `"type": "agent"` without a `"prompt"` field to describe the sub-agent's task.

## Pass / Fail

### Pass

```json
{ "type": "prompt", "prompt": "Check for security issues" }
```

### Fail

```json
{ "type": "prompt", "matcher": "Edit" }
```

## Limitations

Checks every handler typed `"prompt"` or `"agent"` in the `"hooks"` block for its own non-empty `"prompt"` field, and reports every handler that lacks one on the line where it starts. Agent-specific rules supersede with each agent's own handler types. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
