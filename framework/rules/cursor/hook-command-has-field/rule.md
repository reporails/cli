---
id: CURSOR:S:0004
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://cursor.com/docs/hooks
supersedes: CORE:S:0029
---

# Hook Command Has Field

Hook handlers with `"type": "command"` in `.cursor/hooks.json` MUST include a `"command"` field containing the shell command to execute. Without it, Cursor has no command to run and the hook fails silently.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` which passes the key check but executes nothing.

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

Checks that at least one handler has a command field with a non-empty value.
