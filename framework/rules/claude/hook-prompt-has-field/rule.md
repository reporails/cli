---
id: CLAUDE:S:0007
slug: hook-prompt-has-field
title: Hook Prompt Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
source: https://code.claude.com/docs/en/hooks
supersedes: CORE:S:0030
---

# Hook Prompt Has Field

Hook handlers with `"type": "prompt"` or `"type": "agent"` MUST include a `"prompt"` field containing the instruction text. Without it, Claude Code has no prompt to inject and the hook does nothing.

## Antipatterns

- **Prompt handler without prompt field.** Defining `"type": "prompt"` with a `"matcher"` but no `"prompt"` field. Claude Code has no instruction text to inject.
- **Using command field instead of prompt.** Setting `"type": "prompt"` with a `"command"` field — the handler expects `"prompt"` for instruction text, not `"command"`.
- **Agent handler missing prompt.** Defining `"type": "agent"` without a `"prompt"` field. Agent handlers also require a prompt to define the sub-agent's task.
- **Empty prompt string.** Setting `"prompt": ""` — the key is present but there is no instruction to inject.

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

Checks each `"type": "prompt"` or `"type": "agent"` handler object for its own non-empty `"prompt"` field, and reports every handler that lacks one on the line where it starts. A config with no prompt- or agent-typed handler draws no finding — there is nothing for this check to require a prompt on. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.

