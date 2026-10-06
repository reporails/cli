---
id: COPILOT:S:0003
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
source: https://docs.github.com/en/copilot/reference/hooks-configuration
---

# Hook Valid Event Types

Hook event keys in `.github/hooks/*.json` MUST use a recognized Copilot event type name. The Copilot hooks reference accepts both the camelCase form (`sessionStart`, `preToolUse`, `userPromptSubmitted`, …) and its PascalCase alias (`SessionStart`, `PreToolUse`, `UserPromptSubmit`, …) — either casing fires the hook. An unrecognized name in neither list is silently ignored, so the hook never fires.

## Antipatterns

- **Made-up casing.** Writing `OnToolUse` or `on_tool_use` — neither the camelCase nor the PascalCase form.
- **Cross-agent event names.** Using an event name Copilot does not document (e.g. another agent's hook vocabulary).
- **Deprecated event names.** Using event names from older versions that have been renamed or removed.

## Pass / Fail

### Pass

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{ "type": "command", "bash": "./guard.sh" }]
  }
}
```

### Fail

```json
{
  "version": 1,
  "hooks": {
    "onToolUse": [{ "type": "command", "command": "echo hook" }]
  }
}
```

## Limitations

Checks that at least one recognized Copilot event type (either casing) is present, and separately flags a key shaped like an event name (an array of handler objects) that is not a recognized name, so a typo next to a valid event is still caught.
