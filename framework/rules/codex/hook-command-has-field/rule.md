---
id: CODEX:S:0005
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
supersedes: CORE:S:0029
source: https://developers.openai.com/codex/hooks
---

# Hook Command Has Field

Hook handlers with `"type": "command"` in `.codex/hooks.json` MUST include a `"command"` field containing the shell command to execute. Without it, Codex has no command to run and the hook fails silently.

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
