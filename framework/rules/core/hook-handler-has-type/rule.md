---
id: CORE:S:0028
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
depends_on: [CORE:S:0027]
---

# Hook Handler Has Type

Hook configuration must contain at least one `"type"` key. Without a type field, the agent cannot dispatch handlers. Agent-specific rules supersede with the valid type enum per agent.

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

Checks for any `"type":` key in the config file. Does not verify the type value is valid or that the field is inside a hook handler object. Agent-specific rules supersede with per-agent type enum validation.
