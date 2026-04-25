---
id: CORE:S:0029
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
depends_on: [CORE:S:0027]
---

# Hook Command Has Field

Hook configuration must contain at least one `"command"` key with a non-empty string value. The check scans for `"command": "..."` anywhere in the config file.

## Antipatterns

- **Missing command field.** Defining `"type": "command"` without a `"command"` key.
- **Empty command string.** Setting `"command": ""` — the regex requires at least one character.
- **Command in wrong location.** A `"command"` key outside the hooks block satisfies this check but may not function as a hook.

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

Checks for any `"command": "..."` pattern in the file. Does not verify the field is inside a hook handler or that the handler's type is `"command"`. Agent-specific rules supersede with additional context.
