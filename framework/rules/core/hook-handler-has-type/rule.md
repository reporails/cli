---
id: CORE:S:0028
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
requires_capability: hooks
---

# Hook Handler Has Type

At least one handler in the `"hooks"` block must carry a `"type"`. Without a type field, the agent cannot dispatch handlers. Agent-specific rules supersede with the valid type enum per agent.

## Antipatterns

- **Missing type field.** Defining a handler with `"command"` but no `"type"` key.
- **Type outside hooks block.** Having a `"type"` field in non-hook config sections where it serves a different purpose.
- **Invalid type value.** Using `"type": "shell"` instead of the agent's recognized values.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [{ "type": "command", "command": "echo pre" }]
  }
}
```

### Fail

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "echo pre" }]
  }
}
```

## Limitations

Checks that at least one handler in the `"hooks"` block carries a `"type"`; a `"type"` elsewhere in the file does not count. Does not verify the type value is valid. A hooks block with no handler, or a file that is not valid JSON, draws no finding here. Agent-specific rules supersede with per-agent type enum validation.
