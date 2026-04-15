---
id: CORE:S:0002
slug: section-headers-present
title: "Section Headers Present"
category: structure
type: mechanical
severity: critical
backed_by: []
match: {format: freeform}
---
# Section Headers Present

Each instruction file must contain markdown section headers (lines starting with `#`). Headers organize content into navigable sections that help agents locate relevant instructions.

## Antipatterns

- Writing a flat wall of text with no headings. Even short instruction files need at least one heading to establish structure.
- Using bold text (`**Section Name**`) instead of markdown headings (`## Section Name`). Bold text looks like a heading to humans but is not detected as a heading by the check.
- Relying on horizontal rules (`---`) to separate sections instead of headings. Horizontal rules create visual breaks but do not provide navigable structure.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

Use `uv sync` to install dependencies.

## Testing

Run `uv run pytest tests/` for the test suite.
~~~~

### Fail

~~~~markdown
Use uv sync to install dependencies.

Run pytest for the test suite.

Keep files under 500 lines.
~~~~

## Limitations

Uses content analysis on mapped instruction atoms. Results depend on mapper quality and may miss edge cases.
