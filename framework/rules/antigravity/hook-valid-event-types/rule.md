---
id: ANTIGRAVITY:S:0001
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
supersedes: CORE:S:0027
source: https://antigravity.google/docs/gcli-migration
---

# Hook Valid Event Types

Hook event keys in `.gemini/settings.json` MUST use recognized hook event type names (11 events). Unrecognized event names are silently ignored, so a typo means the hook never fires. Antigravity keeps the Hooks surface from Gemini CLI; the event-type set here is inherited pending published Antigravity hook docs.

## Antipatterns

- **Camel-case typos.** Writing event names with wrong capitalization. The agent silently ignores unrecognized keys.
- **Cross-agent event names.** Using event names from another agent (e.g., Claude's `PreToolUse` instead of the `.gemini/settings.json` convention).
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

Checks that at least one recognized event type is present. Does not detect misspelled event names if a valid one also exists. The event-type set is inherited from Gemini CLI pending accessible Antigravity hook documentation.
