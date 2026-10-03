---
id: CURSOR:S:0003
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
source: https://cursor.com/docs/hooks
supersedes: CORE:S:0028
---

# Hook Handler Has Type

A hook handler object in `.cursor/hooks.json` MAY set a `"type"` field to `command` or `prompt`. Cursor's docs list `command` as the default when `"type"` is omitted, so leaving it out is valid — but an explicit value other than `command`/`prompt` is never dispatched.

## Antipatterns

- **Invalid type value.** Setting `"type": "shell"` or `"type": "script"` instead of `command` or `prompt`.
- **Wrong agent's type name.** Copying a hook type from another agent's docs that Cursor does not implement.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "afterFileEdit": [
      { "command": "./hooks/format.sh" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "sessionStart": [
      { "type": "shell", "command": "echo hook" }
    ]
  }
}
```

## Limitations

Only flags an explicit `"type"` value outside `command`/`prompt`. A handler that omits `"type"` entirely is valid (defaults to `command`) and draws no finding. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
