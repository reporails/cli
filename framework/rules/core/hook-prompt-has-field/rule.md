---
id: CORE:S:0030
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
depends_on: [CORE:S:0027]
---

# Hook Prompt Has Field

Hook configuration must contain at least one `"prompt"` key with a non-empty string value. The check scans for `"prompt": "..."` anywhere in the config file.

## Antipatterns

- **Missing prompt field.** Defining `"type": "prompt"` without a `"prompt"` key.
- **Empty prompt string.** Setting `"prompt": ""` — the regex requires at least one character.
- **Prompt in wrong location.** A `"prompt"` key outside the hooks block satisfies this check but may not function as a hook.

## Pass / Fail

### Pass

```json
{ "type": "prompt", "prompt": "Check for security issues" }
```

### Fail

```json
{ "type": "prompt" }
```

## Limitations

Checks for any `"prompt": "..."` pattern in the file. Does not verify the field is inside a hook handler or that the handler's type is `"prompt"` or `"agent"`. Agent-specific rules supersede with additional context.
