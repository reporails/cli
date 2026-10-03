---
id: ANTIGRAVITY:S:0001
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: hooks}
supersedes: CORE:S:0027
source: https://antigravity.google/docs/hooks/
---

# Hook Valid Event Types

Hook event keys in `.agents/hooks.json` (or the global `~/.gemini/config/hooks.json`) MUST use recognized hook event type names (5 events: `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`). Unrecognized event names are silently ignored, so a typo means the hook never fires.

## Antipatterns

- **Camel-case typos.** Writing event names with wrong capitalization, such as `"posttooluse"` or `"PreTOOLUse"`. The agent silently ignores unrecognized keys.
- **Cross-agent event names.** Using event names from another agent's convention (e.g. Gemini-CLI's `SessionStart` or Claude's `SubagentStop`) instead of the 5 Antigravity hook events.
- **Deprecated event names.** Using event names from older versions that have been renamed or removed.

## Pass / Fail

### Pass

```json
{
  "my-linter-hook": {
    "PostToolUse": [
      {
        "matcher": "run_command",
        "hooks": [{ "type": "command", "command": "./scripts/lint.sh" }]
      }
    ]
  }
}
```

### Fail

```json
{
  "my-linter-hook": {
    "onToolUse": [
      {
        "matcher": "run_command",
        "hooks": [{ "type": "command", "command": "./scripts/lint.sh" }]
      }
    ]
  }
}
```

## Limitations

Checks that at least one recognized event type is present, and separately flags a key shaped like an event name that isn't one of the 5 recognized names — so a typo next to a valid event is still caught. Does not evaluate matcher or handler contents.
