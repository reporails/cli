---
id: COPILOT:S:0003
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
supersedes: CORE:S:0027
source: https://code.visualstudio.com/docs/copilot/customization/hooks
---

# Hook Valid Event Types

Hook event keys in `.github/hooks/*.json` or VS Code hook config MUST use recognized Copilot event type names. The VS Code Copilot doc lists eight events in PascalCase: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PreCompact`, `SubagentStart`, `SubagentStop`, `Stop`. Unrecognized event names — including camelCase variants like `preToolUse` — are silently ignored, so the hook never fires.

## Antipatterns

- **camelCase variants.** Writing `preToolUse`, `sessionStart`, or `userPromptSubmitted` — Copilot's event names are uniformly PascalCase, and the camelCase aliases are not recognized.
- **Cross-agent event names.** Using event names from another agent (e.g., `SessionEnd` is a Claude/Cursor event, not a Copilot one).
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

Checks that at least one recognized Copilot event type is present. Does not detect misspelled event names if a valid one also exists.
