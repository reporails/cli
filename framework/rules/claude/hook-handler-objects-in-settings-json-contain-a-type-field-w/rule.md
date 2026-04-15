---
id: CLAUDE:S:0006
slug: hook-handler-objects-in-settings-json-contain-a-type-field-w
title: Hook Handler Objects In Settings Json Contain A Type Field With Value 
  Command, Prompt, Or Agent
category: structure
type: deterministic
severity: high
backed_by:
- claude-code-hooks
match: {type: config}
---

# Hook Handler Type Field Required

Each hook handler object in `.claude/settings.json` MUST contain a `"type"` field set to `"command"`, `"prompt"`, or `"agent"`. Without a type field, Claude Code cannot dispatch the handler and the hook silently does nothing.

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

