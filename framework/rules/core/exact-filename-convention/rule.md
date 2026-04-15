---
id: CORE:S:0004
slug: exact-filename-convention
title: "Exact Filename Convention"
category: structure
type: mechanical
severity: high
backed_by: []
match: {format: [freeform, frontmatter, schema_validated]}
---

# Exact Filename Convention

Instruction filenames must contain only alphanumeric characters, dots, underscores, and dashes — matching the pattern `^[A-Za-z0-9._-]+$`. This prevents encoding issues, shell escaping problems, and path resolution failures across platforms.

## Antipatterns

- **Spaces in filenames** like `my rules.md` — spaces break shell commands and require quoting in every context.
- **Special characters** like `rules@v2.md` or `check(1).yml` — characters outside the allowed set cause path resolution failures on some platforms.
- **Unicode or accented characters** like `regles.md` — the pattern allows only ASCII alphanumerics, dots, underscores, and dashes.

## Pass / Fail

### Pass

~~~~markdown
CLAUDE.md
.cursorrules
my-config_v2.yml
SKILL.md
~~~~

### Fail

~~~~markdown
my rules.md
config (copy).yml
rules@latest.md
~~~~

## Limitations

Checks that the expected file exists. Does not evaluate file contents.
