---
id: CORE:S:0027
slug: hook-valid-event-types
title: Hook Valid Event Types
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
---

# Hook Valid Event Types

Config files must contain a `"hooks"` key. This base rule gates hook validation — agent-specific rules (Claude, Codex, Copilot, Cursor, Gemini) supersede with checks for recognized event names per agent.

## Antipatterns

- **No hooks key.** A config file with hook-related content but no `"hooks"` JSON key.
- **Hooks defined outside config.** Placing hook configuration in instruction files instead of the agent's config file.
- **Empty hooks object.** Including `"hooks": {}` satisfies the presence check but defines no event handlers.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [{ "type": "command", "command": "echo pre" }]
  }
}
```

### Fail

```json
{
  "permissions": { "allow": ["Bash"] }
}
```

## Limitations

Checks only for the presence of a `"hooks"` key via regex. Does not validate event type names. Agent-specific rules supersede with per-agent event name vocabularies.
