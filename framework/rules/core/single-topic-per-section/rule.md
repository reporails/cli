---
id: CORE:S:0019
slug: single-topic-per-section
title: Single Topic Per Section
category: structure
type: mechanical
severity: medium
backed_by: [developer-context-cursor-study, lost-in-the-middle-long-contexts, openai-community-agents-md-optimization,
  rules-directory-mechanics, spec-writing-for-agents]
match: {format: freeform}
---
# Single Topic Per Section

The instruction file must have layered structure with at least 3 headings. Sufficient heading count indicates that content is split into focused sections rather than lumped under one or two broad headings.

## Antipatterns

- Putting testing instructions, formatting rules, and security constraints all under a single "## Guidelines" heading. Each concern should have its own heading section.
- Using only a title heading and one section heading for a file that covers multiple topics. The check requires at least 3 headings to confirm adequate topic separation.
- Adding content at the end of a section that belongs to a different topic rather than creating a new heading.

## Pass / Fail

### Pass

~~~~markdown
# Project
## Testing
Run `uv run pytest tests/`.
## Formatting
Use `ruff` for all formatting.
## Boundaries
NEVER modify `.env` files.
~~~~

### Fail

~~~~markdown
# Project
## Guidelines
Run pytest. Use ruff. Don't modify .env files.
~~~~

## Limitations

Checks that the file uses headings to organize content. Does not evaluate whether the organization is logical or complete.
