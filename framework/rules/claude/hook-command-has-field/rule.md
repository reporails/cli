---
id: CLAUDE:S:0004
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0029
---

# Hook Command Has Field

Hook handlers with `"type": "command"` MUST include a `"command"` field containing the shell command to execute. Without it, Claude Code has no command to run and the hook fails silently.

## Antipatterns

- **Command handler without command field.** Defining `"type": "command"` with a `"matcher"` or `"prompt"` field but forgetting the `"command"` field. Claude Code has nothing to execute.
- **Wrong field name.** Using `"cmd"`, `"script"`, or `"exec"` instead of `"command"`. Only the exact key `"command"` is recognized.
- **Empty command string.** Setting `"command": ""` — technically present but produces no useful execution.

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

