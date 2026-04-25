---
id: CORE:S:0024
slug: import-targets-resolve
title: Import Targets Resolve
category: structure
type: mechanical
severity: medium
backed_by: [developer-context-cursor-study]
match: {format: freeform}
---

# Import Targets Resolve

Import references in instruction files must resolve to existing files. Broken imports create gaps in the agent's context — the agent silently skips missing files without warning.

## Antipatterns

- **Renamed file without updating imports**: Moving `docs/setup.md` to `docs/getting-started.md` but leaving `@import docs/setup.md` in another file. The `extract_imports` check finds the reference and `check_import_targets_exist` fails because the path no longer resolves.
- **Relative path from wrong directory**: Writing `@import ../shared/config.md` when the file structure requires `@import ../../shared/config.md`. The path resolution check verifies the target exists relative to the project root.
- **Import referencing a directory instead of a file**: Writing `@import docs/specs/` instead of `@import docs/specs/pipeline.md`. The check expects file paths, not directory paths.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

@import docs/getting-started.md
@import .claude/rules/testing-design.md
~~~~

### Fail

~~~~markdown
# Project Setup

@import docs/old-setup.md
@import .claude/rules/deleted-rule.md
~~~~

## Limitations

Extracts `@import` references and verifies each target file exists on disk. Does not validate the content of imported files, detect circular imports, or check import syntax correctness.
