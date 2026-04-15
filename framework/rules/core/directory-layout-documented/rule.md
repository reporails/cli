---
id: CORE:C:0035
slug: directory-layout-documented
title: "Directory Layout Documented"
category: coherence
type: deterministic
severity: high
backed_by: []
match: {type: main}
---

# Directory Layout Documented

The main instruction file must include a section documenting the project's directory layout using a heading like "Structure", "Architecture", "Layout", or "Directory" and containing a tree listing or path references. Without a visible directory map, the agent cannot reliably locate or place files.

## Antipatterns

- **Heading without content** like `## Structure` followed by prose that says "see the repo" — the heading matches but the deterministic pattern requires tree characters or path references underneath.
- **Describing layout in prose only** like "Source code lives in the src directory and tests are in tests" — the check requires structural markers (`/`, tree characters) not just prose mentions.
- **Layout in a separate file** with no reference in the main file — the check targets `type: main`, so the layout must appear in `CLAUDE.md` or equivalent.

## Pass / Fail

### Pass

~~~~markdown
## Structure
```
src/
├── core/
├── interfaces/
└── formatters/
tests/
```
~~~~

### Fail

~~~~markdown
The project has source code and tests organized in directories.
See the repository for the full structure.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
