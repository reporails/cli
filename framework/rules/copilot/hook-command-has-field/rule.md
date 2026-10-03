---
id: COPILOT:S:0005
slug: hook-command-has-field
title: Hook Command Has Field
category: structure
type: deterministic
enforcement_required: true
enforcement_mechanism: hook
severity: high
backed_by: []
match: {type: [config, hooks]}
supersedes: CORE:S:0029
source: https://docs.github.com/en/copilot/reference/hooks-configuration
---

# Hook Command Has Field

A command hook handler in `.github/hooks/*.json` MUST include at least one of `"bash"`, `"powershell"`, `"command"`, or `"exec"` with a non-empty value — the Copilot hooks reference requires one of these four to name the executable. Without one, Copilot has nothing to run and the hook fails silently. A command handler is one with `"type": "command"`, or one that omits `"type"`, which Copilot runs as a command.

## Antipatterns

- **Missing executable field.** Defining `"type": "command"` without any of `bash`/`powershell`/`command`/`exec`.
- **Empty value.** Setting `"command": ""` which passes the key check but executes nothing.
- **Relying on a sibling handler.** One handler's `"bash"` does not cover another command handler that has no executable field of its own.

## Pass / Fail

### Pass

```json
{ "type": "command", "bash": "npm run lint" }
```

### Fail

```json
{ "type": "command" }
```

## Limitations

Checks each command handler for its own non-empty `bash`, `powershell`, `command`, or `exec` field, and reports every handler that lacks all four on the line where it starts. Handlers of type `http` or `prompt` draw no finding. A key inside the handler's `env` object does not count as its executable. Only handlers inside the hook block are read; a file that is not valid JSON draws no finding here.
