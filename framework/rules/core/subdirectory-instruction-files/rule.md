---
id: CORE:S:0037
slug: subdirectory-instruction-files
title: "Subdirectory Instruction Files"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {cardinality: hierarchical}
---

# Subdirectory Instruction Files

Subdirectory instruction files must contain directive content -- actionable instructions the agent can follow. Files without directives or constraints waste the agent's context window without providing guidance.

## Antipatterns

- Creating a subdirectory instruction file that only contains a title heading and no directives. The check requires at least one directive atom (an instruction the agent can act on).
- Filling the file with passive descriptions ("This directory contains utility functions") without any imperatives. Descriptions are not directives.
- Copying boilerplate from the root instruction file without adding subdirectory-specific guidance. The file must contain its own directive content.

## Pass / Fail

### Pass

~~~~markdown
# Utils

Use `snake_case` for all function names in this directory.
NEVER import from `src/reporails_cli/interfaces/` -- utils must not depend on interface code.
~~~~

### Fail

~~~~markdown
# Utils

This directory contains utility functions for the project.
~~~~

## Limitations

Checks that subdirectory instruction files contain directive content. Does not evaluate directive quality or completeness.
