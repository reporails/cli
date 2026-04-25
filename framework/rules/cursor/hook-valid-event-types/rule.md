---
id: CURSOR:S:0002
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://cursor.com/docs/hooks
supersedes: CORE:S:0027
---

# Hook Valid Event Types

Hook event keys in `.cursor/hooks.json` MUST use recognized Cursor event type names (18 events). Unrecognized event names are silently ignored, so a typo means the hook never fires.

## Antipatterns

- **Camel-case typos.** Writing event names with wrong capitalization. Cursor silently ignores unrecognized keys.
- **Cross-agent event names.** Using event names from another agent (e.g., Claude's `PreToolUse` instead of Cursor's convention).
- **Deprecated event names.** Using event names from older versions that have been renamed or removed.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "sessionStart": [{ "type": "command", "command": "echo hook" }]
  }
}
```

### Fail

```json
{
  "hooks": {
    "onToolUse": [{ "type": "command", "command": "echo hook" }]
  }
}
```

## Limitations

Checks that at least one recognized Cursor event type is present. Does not detect misspelled event names if a valid one also exists.
