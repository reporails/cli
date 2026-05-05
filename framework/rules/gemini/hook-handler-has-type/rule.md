---
id: GEMINI:S:0002
slug: hook-handler-has-type
title: Hook Handler Has Type
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
supersedes: CORE:S:0028
source: https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md
---

# Hook Handler Has Type

Each hook handler object in `.gemini/settings.json` MUST contain a `"type"` field set to `command`. The Gemini CLI hooks reference states "Currently only `command` is supported." Without a type field, Gemini CLI cannot dispatch the handler and the hook silently does nothing.

## Antipatterns

- **Missing type field.** Defining a handler with only `"command"` but no `"type"` key.
- **Invalid type value.** Setting `"type": "prompt"`, `"type": "shell"`, or `"type": "script"` — Gemini supports only `command`. (`prompt` is a Claude-specific hook type and is not recognized by Gemini.)

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "SessionStart": [
      { "type": "command", "command": "echo hook" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "SessionStart": [
      { "command": "echo hook" }
    ]
  }
}
```

## Limitations

Checks that at least one handler has a valid type field. Does not verify every handler individually.
