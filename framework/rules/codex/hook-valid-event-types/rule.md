---
id: CODEX:S:0003
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
supersedes: CORE:S:0027
source: https://developers.openai.com/codex/hooks
---

# Hook Valid Event Types

Hook event keys in `.codex/hooks.json` MUST use recognized Codex event type names (6 events). Unrecognized event names are silently ignored, so a typo means the hook never fires.

## Antipatterns

- **Camel-case typos.** Writing event names with wrong capitalization. Codex silently ignores unrecognized keys.
- **Cross-agent event names.** Using event names from another agent (e.g., Claude's `PreToolUse` instead of Codex's convention).
- **Deprecated event names.** Using event names from older versions that have been renamed or removed.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "SessionStart": [{ "type": "command", "command": "echo hook" }]
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

Checks that at least one recognized Codex event type is present. Does not detect misspelled event names if a valid one also exists.
