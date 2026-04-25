---
id: CLAUDE:G:0001
slug: hook-uses-project-dir
title: Hook Uses Project Dir Variable
category: governance
type: deterministic
severity: medium
backed_by: []
match: {type: config}
supersedes: CORE:G:0006
source: https://code.claude.com/docs/en/hooks
---

# Hook Uses Project Dir Variable

Hook shell commands SHOULD reference `$CLAUDE_PROJECT_DIR` or `$CLAUDE_ENV_FILE` instead of hardcoded absolute paths. Claude Code injects these environment variables at runtime — using them makes hooks portable across machines and collaborators.

## Antipatterns

- **Hardcoded home directory.** Writing `"/home/user/project/.claude/hooks/lint.sh"` — breaks when another developer clones the repo or CI runs the hooks.
- **Relative paths without anchor.** Using `".claude/hooks/lint.sh"` without `$CLAUDE_PROJECT_DIR` — the working directory during hook execution may not be the project root.
- **Hardcoded in committed settings.** Absolute paths in `.claude/settings.json` (committed) rather than `.claude/settings.local.json` (gitignored). Every collaborator sees the wrong path.

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

