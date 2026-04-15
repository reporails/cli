---
id: CORE:S:0008
slug: expected-directories-exist
title: "Expected Directories Exist"
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: config}
---

# Expected Directories Exist

Configuration files referenced by instruction files must exist on disk. The check verifies that at least one config-type file is present, serving as a gate for directory structure validation.

## Antipatterns

- **Declaring directories in instructions that do not exist** like referencing `.claude/rules/` when the directory has not been created — the file existence gate fails if no config files are found.
- **Assuming directory creation is automatic** like adding a `config.yml` reference without creating the directory tree first — the check requires files to be present on disk.
- **Referencing config paths only in prose** without actually having the config files — the mechanical check tests file existence, not prose content.

## Pass / Fail

### Pass

~~~~markdown
project/
  .claude/settings.json     (exists on disk)
  .ails/backbone.yml         (exists on disk)
~~~~

### Fail

~~~~markdown
project/
  (no config files present on disk)
  CLAUDE.md references .claude/rules/ but directory is empty
~~~~

## Limitations

Checks that expected directories exist on disk. Does not evaluate directory contents or verify all expected directories are declared.
