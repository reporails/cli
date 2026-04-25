---
id: CLAUDE:S:0007
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0030
---

# Hook Prompt Has Field

Hook handlers with `"type": "prompt"` or `"type": "agent"` MUST include a `"prompt"` field containing the instruction text. Without it, Claude Code has no prompt to inject and the hook does nothing.

## Antipatterns

- **Prompt handler without prompt field.** Defining `"type": "prompt"` with a `"matcher"` but no `"prompt"` field. Claude Code has no instruction text to inject.
- **Using command field instead of prompt.** Setting `"type": "prompt"` with a `"command"` field — the handler expects `"prompt"` for instruction text, not `"command"`.
- **Agent handler missing prompt.** Defining `"type": "agent"` without a `"prompt"` field. Agent handlers also require a prompt to define the sub-agent's task.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "prompt", "prompt": "Check for security issues before proceeding" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "prompt", "matcher": "Edit" }
    ]
  }
}
```

## Limitations

Checks that at least one `"prompt"` field exists. Does not verify the prompt pairs correctly with a `"type": "prompt"` or `"type": "agent"` handler.

