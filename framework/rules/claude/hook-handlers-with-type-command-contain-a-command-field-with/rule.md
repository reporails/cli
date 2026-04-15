---
id: CLAUDE:S:0004
slug: hook-handlers-with-type-command-contain-a-command-field-with
title: Hook Handlers With Type Command Contain A Command Field With The Shell 
  Command To Execute
category: structure
type: deterministic
severity: high
backed_by:
- claude-code-hooks
- claude-code-settings
match: {type: config}
---

# Hook Command Field Required

Hook handlers with `"type": "command"` MUST include a `"command"` field containing the shell command to execute. Without it, Claude Code has no command to run and the hook fails silently.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "/bin/bash .claude/hooks/lint.sh" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "matcher": "Edit" }
    ]
  }
}
```

## Limitations

Checks that at least one `"command"` field exists in the settings file. Does not verify the command is a valid executable or that it pairs correctly with a `"type": "command"` handler.

