---
id: ANTIGRAVITY:S:0002
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: hooks}
supersedes: CORE:S:0028
source: https://antigravity.google/docs/hooks/
---

# Hook Handler Has Type

A hook handler in `.agents/hooks.json` MAY set a `"type"` field, and when it does the value MUST be `command` — the only supported handler type. The docs list `command` as the default when `"type"` is omitted, so leaving it out is valid. A handler with any other type is never dispatched and the hook silently does nothing.

## Antipatterns

- **Invalid type value.** Setting `"type": "prompt"`, `"type": "shell"`, or `"type": "script"` — only `command` is supported. (`prompt` is a Claude-specific hook type and is not recognized here.)

## Pass / Fail

### Pass

```json
{
  "safety-gate": {
    "PreToolUse": [
      { "matcher": "run_command", "hooks": [{ "command": "./scripts/safety-check.sh" }] }
    ]
  }
}
```

### Fail

```json
{
  "reviewer": {
    "PostToolUse": [
      { "matcher": "run_command", "hooks": [{ "type": "prompt", "command": "./scripts/review.sh" }] }
    ]
  }
}
```

## Limitations

Checks each handler object on its own and reports every one whose `"type"` is set to anything other than `command`, on the line where it starts. A handler that omits `"type"` draws no finding. A matcher group (an object holding a `"hooks"` list) is not read as a handler. Only handlers under a named hook's events are read; a file that is not valid JSON draws no finding here.
