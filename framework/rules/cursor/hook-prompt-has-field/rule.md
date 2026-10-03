---
id: CURSOR:S:0005
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
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

A hooks file with no `"type": "prompt"` handler at all — e.g. only `{ "command": "./hooks/format.sh" }` — also passes: there is no prompt handler for this check to require a prompt on.

## Limitations

Checks each `"type": "prompt"` handler object for its own non-empty `"prompt"` field, and reports every handler that lacks one on the line where it starts. A config with no prompt-typed handler draws no finding. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
