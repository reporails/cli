---
id: CURSOR:S:0007
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
source: https://cursor.com/docs/hooks
---

# Hook Event Handlers

A `"hooks"` block in `.cursor/hooks.json` must list at least one handler under an event. A handler names what it runs: a `"command"`, or `"type": "prompt"` with a `"prompt"`. Cursor runs a handler with no `"type"` as a command, so `{ "command": "./.cursor/hooks/format.sh" }` is a complete handler. A file with no `"hooks"` key is not this rule's concern.

## Antipatterns

- **Empty hooks block.** Declaring `"hooks": {}` or an event with an empty list, so no handler is registered.
- **Handler that runs nothing.** Listing an object such as `{ "timeout": 30 }` with no `"command"`, `"prompt"`, or `"type"`.

## Pass / Fail

### Pass

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": ".cursor/hooks/guard.sh" }],
    "afterFileEdit": [{ "command": ".cursor/hooks/format.sh" }]
  }
}
```

### Fail

```json
{ "version": 1, "hooks": {} }
```

## Limitations

Looks for a `"type"`, `"command"`, or `"prompt"` field inside the `"hooks"` block itself, not in an unrelated key after it. Does not check that the handler's command exists or that its event name is valid; the command-field and event-type rules cover those.
