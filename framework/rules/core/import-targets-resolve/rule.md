---
id: CORE:S:0024
slug: import-targets-resolve
title: Import Targets Resolve
category: structure
type: mechanical
severity: high
backed_by: [developer-context-cursor-study]
match: {format: [freeform, frontmatter]}
---

# Import Targets Resolve

Import references in instruction files must resolve to existing files. Broken imports create gaps in the agent's context — the agent silently skips missing files without warning.

## Antipatterns

- **Renamed file without updating imports**: Moving `docs/setup.md` to `docs/getting-started.md` but leaving `@docs/setup.md` in another file. The `extract_imports` check finds the reference and `check_import_targets_exist` fails because the path no longer resolves.
- **Relative path from wrong directory**: Writing `@../shared/config.md` when the file structure requires `@../../shared/config.md`. The path resolution check verifies the target exists relative to the project root.
- **Import referencing a directory instead of a file**: Writing `@docs/specs/` instead of `@docs/specs/pipeline.md`. The check expects file paths, not directory paths.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

@docs/getting-started.md
@.claude/rules/testing-design.md
~~~~

### Fail

~~~~markdown
# Project Setup

@docs/old-setup.md
@.claude/rules/deleted-rule.md
~~~~

## Limitations

Extracts `@<path>` references via `extract_imports` (regex `@[\w./-]+`) and verifies each target file exists on disk via `check_import_targets_exist`. Does not validate the content of imported files, detect circular imports, or check whether the regex captured trailing punctuation in inline references.
