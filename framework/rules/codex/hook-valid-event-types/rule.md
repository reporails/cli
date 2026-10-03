---
id: CODEX:S:0003
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
supersedes: CORE:S:0027
source: https://learn.chatgpt.com/docs/hooks
---

# Hook Valid Event Types

Hook event keys in `.codex/hooks.json` (or an inline `[hooks]` table in `config.toml`) MUST use recognized Codex event type names (12 events: `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `Stop`, `Interrupt`). Unrecognized event names are silently ignored, so a typo means the hook never fires.

## Antipatterns

- **Camel-case typos.** Writing event names with wrong capitalization. Codex silently ignores unrecognized keys.
- **Cross-agent event names.** Using event names from another agent's convention instead of Codex's 12 events.
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

Checks that at least one recognized Codex event type is present, and separately flags a key shaped like an event name that isn't one of the 12 recognized names — so a typo next to a valid event is still caught.
