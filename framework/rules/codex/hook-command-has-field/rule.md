---
id: CODEX:S:0005
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
supersedes: CORE:S:0029
source: https://learn.chatgpt.com/docs/hooks
---

# Hook Command Has Field

Hook handlers with `"type": "command"` in `.codex/hooks.json` (or an inline `[hooks]` table in `config.toml`) MUST include a `"command"` field containing the shell command to execute. Without it, Codex has no command to run and the hook fails silently.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` which passes the key check but executes nothing.
- **Relying on a sibling handler.** A valid `"command"` on one handler does not cover another `"type": "command"` handler that lacks its own.

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

Checks each `"type": "command"` handler for its own non-empty `"command"` field, and reports every handler that lacks one on the line where it starts. A hooks file with no command handler — for example only `prompt` or `agent` handlers, which Codex skips — draws no finding. Only handlers inside the hook block are read; a file that is not valid JSON or TOML draws no finding here.
