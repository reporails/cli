---
id: CLAUDE:G:0001
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
source: https://code.claude.com/docs/en/hooks
---

# Hook Uses Project Dir Variable

Hook shell commands SHOULD anchor their paths instead of hardcoding absolute ones: a project hook with `$CLAUDE_PROJECT_DIR` (or `$CLAUDE_ENV_FILE`), a plugin's hook with `${CLAUDE_PLUGIN_ROOT}` (or `${CLAUDE_PLUGIN_DATA}`). Claude Code injects these environment variables at runtime — using them makes hooks portable across machines and collaborators.

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

A plugin's `hooks/hooks.json` anchors its script with `${CLAUDE_PLUGIN_ROOT}`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}\"/hooks/heal-notice.sh" }
        ]
      }
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

Fires only when the hooks block has at least one `"type": "command"` handler that runs a command; a config whose hooks are all prompt or agent handlers draws no finding. Checks that at least one of those commands references a Claude environment variable; a reference elsewhere in the file does not count. Does not flag individual commands that use hardcoded paths if other commands already use the variable. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here. The check does not tell a project hook from a plugin hook, so a project hook naming `${CLAUDE_PLUGIN_ROOT}` passes.
