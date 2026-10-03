---
id: CURSOR:S:0004
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
source: https://cursor.com/docs/hooks
supersedes: CORE:S:0029
---

# Hook Command Has Field

Hook handlers in `.cursor/hooks.json` with `"type": "command"` — or with no `"type"`, which Cursor runs as a command — MUST include a `"command"` field containing the shell command to execute. Without it, Cursor has no command to run and the hook fails silently.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` which passes the key check but executes nothing.
- **Prompt handler without its type.** Writing `{ "prompt": "..." }` with no `"type": "prompt"` — Cursor runs it as a command handler, and it has no command.
- **Relying on a sibling handler.** A valid `"command"` on one handler does not cover another command handler that lacks its own.

## Pass / Fail

### Pass

```json
{ "type": "command", "command": "npm run lint" }
```

A hooks file whose only handlers are `"type": "prompt"` also passes: there is no command handler for this check to require a command on.

### Fail

```json
{ "type": "command" }
```

## Limitations

Checks each command handler — `"type": "command"` or no `"type"` — for its own non-empty `"command"` field, and reports every handler that lacks one on the line where it starts. Prompt handlers draw no finding. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
