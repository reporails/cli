---
id: CLAUDE:S:0005
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0027
---

# Hook Valid Event Types

Hook event keys in `.claude/settings.json` MUST use recognized Claude Code event type names (33 events as of 2026-09-30). Unrecognized event names are silently ignored, so a typo like `"PreTooluse"` (lowercase u) means the hook never fires.


## Antipatterns

- **Camel-case typos.** Writing `"PreTooluse"` (lowercase u) or `"postToolUse"` (lowercase p) instead of the exact PascalCase names. Claude Code silently ignores unrecognized keys.
- **Inventing event names.** Using names like `"onToolUse"`, `"before_tool"`, or `"AfterEdit"` that follow familiar conventions but aren't recognized by Claude Code.
- **Legacy or deprecated names.** Using event names from older Claude Code versions that have since been renamed or removed. The valid set changes across versions.

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

Checks that at least one recognized event type is present, and separately flags a key shaped like an event name that isn't one of the 33 recognized names — so a typo next to a valid event is still caught.

