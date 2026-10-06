---
id: CORE:S:0020
slug: hook-event-handlers
title: Hook Event Handlers
category: structure
type: mechanical
enforcement_required: true
enforcement_mechanism: hook
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents, instruction-limits-principles]
match: {type: [config, hooks]}
requires_capability: hooks
---
# Hook Event Handlers

A config file that declares a `"hooks"` block must give at least one handler a `"type"`. A `"hooks"` block with no typed handler leaves the agent with a section that names nothing it can act on. A config file with no `"hooks"` key at all is not this rule's concern — it has not declared hooks, so there is nothing to check.

## Antipatterns

- **Empty hooks block**: Declaring `"hooks": {}` or an event with an empty list, with no handler object underneath. The check looks for a `"type"` field inside the `"hooks"` block itself, not for `"type"` anywhere later in the file.
- **Handler with no type**: Listing a handler object under an event name but leaving out `"type"`. Without a type, the agent cannot tell whether the handler runs a command, a prompt, or something else.
- **Hook logic described only in prose**: Writing about pre-commit behavior in a comment or a separate doc instead of declaring it in the config's own `"hooks"` block. The check reads the config file itself, not prose about it.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "ruff check" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {},
  "statusLine": { "type": "command", "command": "status.sh" }
}
```

## Limitations

Checks for a `"type"` field inside the `"hooks"` block's own value, not in an unrelated key that happens to follow it. Does not verify the type is a recognized handler kind or that it pairs with a valid event name — the agent-specific event-type rules cover that.
