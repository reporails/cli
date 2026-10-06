---
id: ANTIGRAVITY:S:0003
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: hooks}
supersedes: CORE:S:0029
source: https://antigravity.google/docs/hooks/
---

# Hook Command Has Field

Hook handlers in `.agents/hooks.json` with `"type": "command"` — or with no `"type"`, which defaults to `command` — MUST include a `"command"` field containing the shell command to execute. Without it, the agent has no command to run and the hook fails silently.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` which passes the key check but executes nothing.
- **Relying on a sibling handler.** A valid `"command"` on one handler does not cover another command handler that lacks its own.

## Pass / Fail

### Pass

```json
{ "type": "command", "command": "npm run lint" }
```

### Fail

```json
{ "type": "command" }
```

## Limitations

Checks each command handler — `"type": "command"` or no `"type"` — for its own non-empty `"command"` field, and reports every handler that lacks one on the line where it starts. A handler with another type draws no finding here; the handler-type rule reports it. A matcher group (an object holding a `"hooks"` list) is not read as a handler. Only handlers under a named hook's events are read; a file that is not valid JSON draws no finding here. Re-verified 2026-09-30 against antigravity.google/docs/hooks/.
