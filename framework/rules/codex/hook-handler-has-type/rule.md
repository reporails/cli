---
id: CODEX:S:0004
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
source: https://learn.chatgpt.com/docs/hooks
---

# Hook Handler Has Type

Each hook handler object in `.codex/hooks.json` (or an inline `[hooks]` table in `config.toml`) MUST contain a `"type"` field set to `command` or `mcp_tool`. Without a type field, Codex cannot dispatch the handler and the hook silently does nothing.

## Antipatterns

- **Missing type field.** Defining a handler with only `"command"` but no `"type"` key.
- **Invalid type value.** Setting `"type": "shell"` or `"type": "script"` instead of `command` or `mcp_tool`.

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

Checks each handler object on its own and reports every one with no `"type"` or with a type other than `command` or `mcp_tool`, on the line where it starts. `prompt` and `agent` handlers are reported too: Codex parses them but skips them, so they never run. An object counts as a handler when it carries a `"type"`, `"command"`, `"commandWindows"`, `"server"`, `"tool"`, or `"prompt"` field; a matcher group (an object holding a `"hooks"` list) is not a handler. Only handlers inside the hook block are read; a file that is not valid JSON or TOML draws no finding here.
