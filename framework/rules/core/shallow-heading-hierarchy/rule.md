---
id: CORE:S:0003
slug: shallow-heading-hierarchy
title: "Shallow Heading Hierarchy"
category: structure
type: deterministic
severity: high
backed_by: []
match: {format: freeform}
---

# Shallow Heading Hierarchy

Heading hierarchy must stay at 4 levels or fewer -- no `#####` (h5) or deeper headings. Deep nesting makes content harder to scan and signals that the file should be split into smaller files.

## Antipatterns

- Nesting subsections deeply to preserve logical hierarchy (e.g., `##### Edge Case`). The check flags any line starting with 5 or more `#` characters followed by a space.
- Using deep headings to indent content visually. Markdown heading depth is structural, not cosmetic -- use lists or indentation for visual nesting.
- Promoting a subsection to h5 to "fit" it under an h4 parent. Restructure the document to stay within 4 levels instead.

## Pass / Fail

### Pass

~~~~markdown
# Project
## Commands
### Testing
#### Unit Tests
Run `uv run pytest tests/unit/`.
~~~~

### Fail

~~~~markdown
# Project
## Commands
### Testing
#### Unit Tests
##### Edge Cases
Run edge case tests separately.
~~~~

## Limitations

Detects headings deeper than 4 levels. Does not evaluate heading structure or logical nesting.
