---
id: CLAUDE:S:0006
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0028
---

# Hook Handler Has Type

Each hook handler object in `.claude/settings.json` MUST contain a `"type"` field set to `"command"`, `"http"`, `"mcp_tool"`, `"prompt"`, or `"agent"`. Without a type field, Claude Code cannot dispatch the handler and the hook silently does nothing.

## Antipatterns

- **Missing type field.** Defining a handler with only `"command"` or `"prompt"` but no `"type"` key. Claude Code cannot infer the handler type from its other fields.
- **Invalid type value.** Setting `"type": "shell"` or `"type": "script"` instead of the recognized values `"command"`, `"http"`, `"mcp_tool"`, `"prompt"`, or `"agent"`.
- **Type on the event, not the handler.** Placing the `"type"` field at the event level (`"PreToolUse": { "type": "command" }`) instead of inside each handler object in the array.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "npm run lint" },
      { "type": "prompt", "prompt": "Check for security issues" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "PreToolUse": [
      { "command": "npm run lint" }
    ]
  }
}
```

## Limitations

Checks that at least one handler has a valid type field. Does not verify every handler individually when multiple handlers are defined for the same event.

