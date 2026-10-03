---
id: CODEX:S:0006
slug: settings-scope-declared
title: Settings Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage]
match: {type: config}
supersedes: CORE:S:0021
source: https://learn.chatgpt.com/docs/config-file/config-advanced
---
# Settings Scope Declared

A Codex configuration file's scope (project or user) is fixed by which path it lives at, so `config.toml` must declare real settings rather than ship as an empty placeholder. An empty file leaves the agent unable to tell whether the config is unused, mid-setup, or broken.

This is the TOML form of `CORE:S:0021`. A `config.toml` with any top-level key or any table (`[table]`) counts as declaring settings; the JSON settings files of other agents keep the JSON form of the check.

## Antipatterns

- **Empty file**: Committing a `config.toml` with no content. The file exists but declares nothing.
- **Comments only**: A `config.toml` that holds only `#` comment lines. Comments set nothing, so the file is still empty.
- **Placeholder left after scaffolding**: Generating the file from a template and never filling in `model`, `approval_policy`, `sandbox_mode`, an `[mcp_servers.<id>]` table, or another real setting.

## Pass / Fail

### Pass

```toml
model = "your-model"
approval_policy = "on-request"
```

### Fail

```toml
# project settings go here
```

## Limitations

Checks that the file declares at least one key or table. Does not verify that the key names a setting Codex recognizes.
