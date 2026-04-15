---
id: CLAUDE:G:0001
slug: hook-shell-commands-reference-claude-project-dir-instead-of-
title: Hook Shell Commands Reference $Claude Project Dir Instead Of Hardcoded 
  Paths
category: governance
type: deterministic
severity: medium
backed_by:
- claude-code-hooks
- claude-code-settings
match: {type: config}
---

# Hook Commands Use Project Dir Variable

Hook shell commands SHOULD reference `$CLAUDE_PROJECT_DIR` or `$CLAUDE_ENV_FILE` instead of hardcoded absolute paths. Claude Code injects these environment variables at runtime — using them makes hooks portable across machines and collaborators.

## Pass / Fail

### Pass

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/lint.sh" }
    ]
  }
}
```

### Fail

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "/home/user/project/.claude/hooks/lint.sh" }
    ]
  }
}
```

## Limitations

Checks that at least one Claude environment variable reference exists. Does not flag individual commands that use hardcoded paths if other commands already use the variable.

