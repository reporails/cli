---
id: COPILOT:S:0004
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
supersedes: CORE:S:0028
source: https://docs.github.com/en/copilot/reference/hooks-configuration
---

# Hook Handler Has Type

A hook handler object in `.github/hooks/*.json` MAY set a `"type"` field to `command`, `http`, or `prompt`. The Copilot hooks reference states `"type"` defaults to `"command"` when omitted, so leaving it out is valid — but an explicit value outside the three recognized types is never dispatched.

## Antipatterns

- **Invalid type value.** Setting `"type": "shell"` or `"type": "script"` — Copilot recognizes only `command`, `http`, and `prompt`.
- **Wrong agent's type name.** Copying a hook type from another agent's docs that Copilot does not implement.

## Pass / Fail

### Pass

```json
{ "type": "command", "bash": "echo hook" }
```

### Fail

```json
{ "type": "shell", "command": "echo hook" }
```

## Limitations

Only flags an explicit `"type"` value outside `command`/`http`/`prompt`. A handler that omits `"type"` entirely is valid (defaults to `command`) and draws no finding. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
