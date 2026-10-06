---
id: CURSOR:G:0001
slug: hook-uses-project-dir
title: Hook Uses Project Dir Variable
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: medium
backed_by: []
match: {type: [config, hooks]}
supersedes: CORE:G:0006
source: https://cursor.com/docs/hooks
---

# Hook Uses Project Dir Variable

Hook commands in `.cursor/hooks.json` SHOULD NOT hardcode an absolute path such as `/home/user/project/...`. Cursor runs project hooks from the project root, so a path relative to the root (`.cursor/hooks/lint.sh`) works on every machine and clone. When a command needs the root explicitly, use `$CURSOR_PROJECT_DIR`, or its alias `$CLAUDE_PROJECT_DIR` — Cursor sets both on every hook run.

## Antipatterns

- **Hardcoded absolute paths.** Writing `/home/user/project/scripts/lint.sh` instead of `.cursor/hooks/lint.sh` or `$CURSOR_PROJECT_DIR/scripts/lint.sh`.
- **Machine-specific home directory.** Using `/Users/name/project/...`, which fails on Linux and on every other collaborator's machine.

## Pass / Fail

### Pass

```json
{ "command": ".cursor/hooks/lint.sh" }
```

```json
{ "type": "command", "command": "$CURSOR_PROJECT_DIR/scripts/lint.sh" }
```

### Fail

```json
{ "type": "command", "command": "/home/user/project/scripts/lint.sh" }
```

## Limitations

Checks each command handler — `"type": "command"` or no `"type"` — and reports every one whose command starts with `/home/`, `/Users/`, `/tmp/`, `/var/`, `/etc/`, or `/opt/`. Relative paths and paths built on `$CURSOR_PROJECT_DIR` or `$CLAUDE_PROJECT_DIR` draw no finding, and prompt handlers are not checked. Does not detect Windows paths, an absolute path later in the command string, or a relative path that points at the wrong folder. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
