---
id: CLAUDE:S:0005
slug: hook-configuration-uses-recognized-event-type-names-as-keys
title: Hook Configuration Uses Recognized Event Type Names As Keys
category: structure
type: deterministic
severity: high
backed_by:
- claude-code-hooks
- claude-code-settings
match: {type: config}
---

# Hook Configuration Uses Recognized Event Type Names As Keys

Hook event keys in `.claude/settings.json` MUST use recognized Claude Code event type names. Unrecognized event names are silently ignored, so a typo like `"PreTooluse"` (lowercase u) means the hook never fires.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [{ "type": "command", "command": "echo pre" }],
    "PostToolUse": [{ "type": "command", "command": "echo post" }],
    "Stop": [{ "type": "command", "command": "./cleanup.sh" }]
  }
}
```

### Fail

```json
{
  "hooks": {
    "onToolUse": [{ "type": "command", "command": "echo hook" }],
    "before_tool": [{ "type": "command", "command": "echo hook" }]
  }
}
```

## Limitations

Only checks that at least one recognized event type is present. Does not detect misspelled event names if a valid one also exists.

