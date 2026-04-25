---
id: CURSOR:S:0005
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://cursor.com/docs/hooks
supersedes: CORE:S:0030
---

# Hook Prompt Has Field

Hook handlers with `"type": "prompt"` in `.cursor/hooks.json` MUST include a `"prompt"` field containing the instruction text. Without it, Cursor has no prompt to inject and the hook does nothing.

## Antipatterns

- **Missing prompt field.** Defining `"type": "prompt"` without a `"prompt"` key.
- **Empty prompt string.** Setting `"prompt": ""` which passes the key check but provides no instruction.

## Pass / Fail

### Pass

```json
{ "type": "prompt", "prompt": "Check for security issues before approving" }
```

### Fail

```json
{ "type": "prompt" }
```

## Limitations

Checks that at least one handler has a prompt field with a non-empty value.
