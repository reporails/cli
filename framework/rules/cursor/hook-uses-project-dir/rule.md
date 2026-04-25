---
id: CURSOR:G:0001
slug: hook-uses-project-dir
title: Hook Uses Project Dir Variable
category: governance
type: deterministic
severity: medium
backed_by: []
match: {type: config}
supersedes: CORE:G:0006
source: https://cursor.com/docs/hooks
---

# Hook Uses Project Dir Variable

Hook shell commands in `.cursor/hooks.json` SHOULD reference `$CURSOR_PROJECT_DIR` instead of hardcoded absolute paths. Cursor injects this environment variable at runtime — using it makes hooks portable across machines and collaborators.

## Antipatterns

- **Hardcoded absolute paths.** Writing `/home/user/project/scripts/lint.sh` instead of `$CURSOR_PROJECT_DIR/scripts/lint.sh`.
- **Wrong agent variable.** Using another agent's variable (e.g., `$CLAUDE_PROJECT_DIR` in a Cursor project).

## Pass / Fail

### Pass

```json
{ "type": "command", "command": "$CURSOR_PROJECT_DIR/scripts/lint.sh" }
```

### Fail

```json
{ "type": "command", "command": "/home/user/project/scripts/lint.sh" }
```

## Limitations

Checks that at least one hook command references `$CURSOR_PROJECT_DIR`. Does not verify all commands use it.
