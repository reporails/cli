---
id: CLAUDE:S:0006
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
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

Checks each handler object on its own and reports every one with no `"type"` or with a type outside the five, on the line where it starts. An object counts as a handler when it carries a `"type"`, `"command"`, `"url"`, `"prompt"`, `"server"`, or `"tool"` field; a matcher group (an object holding a `"hooks"` list) is not a handler. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.

