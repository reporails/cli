---
id: CORE:S:0021
slug: settings-scope-declared
title: Settings Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage]
match: {type: config}
---
# Settings Scope Declared

A configuration file's scope (project, user, local, or managed) is fixed by which path it lives at, so the file itself must declare real settings rather than ship as an empty placeholder. An empty config leaves the agent unable to tell whether the file is unused, mid-setup, or broken.

## Antipatterns

- **Empty settings object**: Committing `{}` with no top-level key. The file exists but declares nothing, so nothing distinguishes "not yet configured" from "intentionally empty."
- **Placeholder left after scaffolding**: Generating the file from a template and never filling in any of `hooks`, `permissions`, `env`, `mcpServers`, or another real setting.
- **Scope claimed in a comment**: Since JSON carries no comments, a `// project scope` note some tools tolerate is invisible to every JSON-reading agent — the scope comes from the file's path, not from text inside it.

## Pass / Fail

### Pass

```json
{
  "env": { "NODE_ENV": "development" }
}
```

### Fail

```json
{}
```

## Limitations

Checks that the file declares at least one top-level key. Does not verify the key names a setting the agent actually recognizes.
