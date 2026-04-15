---
id: CLAUDE:S:0007
slug: hook-handlers-with-type-prompt-or-agent-contain-a-prompt-fie
title: Hook Handlers With Type Prompt Or Agent Contain A Prompt Field
category: structure
type: deterministic
severity: high
backed_by:
- claude-code-hooks
match: {type: config}
---

# Hook Prompt Field Required

Hook handlers with `"type": "prompt"` or `"type": "agent"` MUST include a `"prompt"` field containing the instruction text. Without it, Claude Code has no prompt to inject and the hook does nothing.

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

