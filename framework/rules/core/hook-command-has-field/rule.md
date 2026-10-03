---
id: CORE:S:0029
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
requires_capability: hooks
---

# Hook Command Has Field

Each hook handler with `"type": "command"` must carry its own `"command"` key with a non-empty string value. The check reads every command handler on its own, so a valid command on one handler does not cover another.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` — the check requires at least one character.
- **Relying on a sibling handler.** A `"command"` on one handler does not cover another `"type": "command"` handler in the same file that lacks its own.

## Pass / Fail

### Pass

```json
{ "type": "command", "command": "npm run lint" }
```

A hooks block whose only handlers are prompt or agent handlers also passes: there is no command handler for this check to require a command on.

### Fail

```json
{ "type": "command" }
```

## Limitations

Checks each `"type": "command"` handler object for its own non-empty `"command"` field, and reports every handler that lacks one on the line where it starts. A handler that omits `"type"` is not read as a command handler here. Agent-specific rules supersede with each agent's own handler shape — an untyped handler that runs as a command, or executable fields other than `"command"`. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
