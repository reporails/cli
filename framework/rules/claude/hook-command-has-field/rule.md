---
id: CLAUDE:S:0004
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0029
---

# Hook Command Has Field

Hook handlers with `"type": "command"` MUST include a `"command"` field containing the shell command to execute. Without it, Claude Code has no command to run and the hook fails silently.

## Antipatterns

- **Command handler without command field.** Defining `"type": "command"` with a `"matcher"` or `"prompt"` field but forgetting the `"command"` field. Claude Code has nothing to execute.
- **Wrong field name.** Using `"cmd"`, `"script"`, or `"exec"` instead of `"command"`. Only the exact key `"command"` is recognized.
- **Empty command string.** Setting `"command": ""` — technically present but produces no useful execution.
- **Relying on a sibling handler.** A valid `"command"` on one handler does not cover another `"type": "command"` handler in the same file that lacks its own.

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

A hooks block whose only handlers are `"type": "prompt"` or `"type": "agent"` also passes: there is no command handler for this check to require a command on.

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

Checks each `"type": "command"` handler object for its own non-empty `"command"` field, and reports every handler that lacks one on the line where it starts. A config with no command-typed handler draws no finding. Does not verify the command is a valid executable. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.

