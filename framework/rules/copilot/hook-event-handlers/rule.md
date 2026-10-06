---
id: COPILOT:S:0006
slug: hook-event-handlers
title: Hook Event Handlers
category: structure
type: mechanical
enforcement_required: true
enforcement_mechanism: hook
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents, instruction-limits-principles]
match: {type: [config, hooks]}
supersedes: CORE:S:0020
source: https://docs.github.com/en/copilot/reference/hooks-configuration
---

# Hook Event Handlers

A `"hooks"` block in `.github/hooks/*.json` must list at least one handler under an event. A handler names what it runs: a `"type"`, or one of `"bash"`, `"powershell"`, `"command"`, or `"exec"`. Copilot runs a handler with no `"type"` as a command, so `{ "bash": "./scripts/guard.sh" }` is a complete handler. A file with no `"hooks"` key is not this rule's concern.

## Antipatterns

- **Empty hooks block.** Declaring `"hooks": {}` or an event with an empty list, so no handler is registered.
- **Handler that runs nothing.** Listing an object such as `{ "timeoutSec": 30 }` with no type and no executable field.

## Pass / Fail

### Pass

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{ "bash": "./scripts/guard.sh", "powershell": "./scripts/guard.ps1" }]
  }
}
```

### Fail

```json
{ "version": 1, "hooks": { "preToolUse": [] } }
```

## Limitations

Looks for a `"type"`, `"bash"`, `"powershell"`, `"command"`, or `"exec"` field inside the `"hooks"` block itself, not in an unrelated key after it. Does not check that the executable exists or that the event name is valid; the command-field and event-type rules cover those.
