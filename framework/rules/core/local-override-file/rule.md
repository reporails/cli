---
id: CORE:S:0022
slug: local-override-file
title: "Local Override File"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: override}
---

# Local Override File

A local override file must exist and contain at least 20 characters of substantive content. Override files allow user-specific customizations without modifying committed instruction files.

## Antipatterns

- **Empty override file**: Creating the file but leaving it blank or with only whitespace. The check requires at least 20 characters of content via the pattern `(?s).{20,}`.
- **Stub-only content**: Writing just `# Override` (10 characters) as a placeholder. This falls below the 20-character minimum because it contains no substantive customization.
- **Override content in the wrong file**: Adding personal preferences to the committed `CLAUDE.md` instead of the local override file. The check targets files with the `override` type specifically.

## Pass / Fail

### Pass

~~~~markdown
# Local Overrides

Use verbose test output: `uv run pytest -v --tb=long`
~~~~

### Fail

~~~~markdown
# Override
~~~~

## Limitations

Checks that the local override file has substantive content (at least 20 characters). Does not evaluate content relevance.
