---
id: CORE:G:0006
slug: hook-uses-project-dir
title: Hook Uses Project Dir Variable
category: governance
type: deterministic
severity: medium
backed_by: []
match: {type: config}
depends_on: [CORE:S:0027]
---

# Hook Uses Project Dir Variable

Hook commands must not contain hardcoded absolute paths like `/home/user/project/`. The check flags `"command"` values that start with common Unix/macOS base directories. Agent-specific rules supersede with checks for the correct project dir variable per agent.

## Antipatterns

- **Hardcoded home directory.** Writing `/home/user/project/scripts/lint.sh` instead of the agent's project dir variable.
- **Hardcoded macOS path.** Using `/Users/name/project/scripts/lint.sh` which fails on Linux and other collaborators' machines.
- **Hardcoded system paths.** Using `/tmp/` or `/var/` paths that vary across environments.

## Pass / Fail

### Pass

```json
{ "type": "command", "command": "$CLAUDE_PROJECT_DIR/scripts/lint.sh" }
```

### Fail

```json
{ "type": "command", "command": "/home/user/project/scripts/lint.sh" }
```

## Limitations

Detects hardcoded absolute paths starting with `/home/`, `/Users/`, `/tmp/`, `/var/`, `/etc/`, or `/opt/` in command values. Does not detect Windows paths or relative paths. Agent-specific rules supersede with checks for the correct project dir variable name.
