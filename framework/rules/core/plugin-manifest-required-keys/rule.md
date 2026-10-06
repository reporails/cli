---
id: CORE:S:0058
slug: plugin-manifest-required-keys
title: Plugin Manifest Required Keys
category: structure
type: deterministic
severity: medium
requires_capability: plugins
backed_by: []
match: {type: plugins}
source: https://code.claude.com/docs/en/plugins
---

# Plugin Manifest Required Keys

A plugin manifest (`.claude-plugin/plugin.json`) must declare `name` and `description`. `name` is the plugin's unique identifier and the namespace every bundled skill is prefixed with (`/<name>:<skill>`); `description` is the text shown in the plugin manager when browsing or installing. A manifest missing `name` has no namespace to mount its skills under; one missing `description` shows blank in the manager. `version` and `author` are optional. Declare `name` and `description` so the plugin installs and displays.

## Antipatterns

- **Manifest with only a version.** Writing `{"version": "1.0.0"}` and relying on the directory name — the manifest namespace comes from `name`, not the folder.
- **Relying on `author.name`.** Declaring `{"author": {"name": "Your Name"}}` and no top-level `name` — the author block names the maintainer, not the plugin, so the manifest still has no namespace.
- **Skipping the description.** Shipping `{"name": "my-plugin"}` with no `description`, so the plugin manager lists it with no summary for users deciding whether to install.

## Pass / Fail

### Pass

```json
{
  "name": "my-plugin",
  "description": "Adds a greeting workflow.",
  "version": "1.0.0",
  "author": { "name": "Your Name" }
}
```

### Fail

```json
{
  "version": "1.0.0"
}
```

## Limitations

Checks that `name` and `description` are present as top-level keys of the manifest object with a non-empty string value. Nested objects and arrays are skipped whole, so a `name` or `description` inside `author` (or any other nested value) does not satisfy the top-level requirement. Does not validate the value shapes of optional keys (`version` semver, `author` object), and does not reject a non-string value.

Fires when the manifest is checked directly: `ails check plugins`, or `ails check .claude-plugin/plugin.json`. A default project scan (`ails check` / `ails check .`, or MCP `validate` on the project) reads instruction and rule files, not the plugin manifest, so a `.claude-plugin/plugin.json` missing `name`/`description` does not appear in it.
