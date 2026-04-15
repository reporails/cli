---
id: CORE:C:0036
slug: priority-ordering
title: "Critical Instructions at Edges"
category: coherence
type: mechanical
severity: high
match: {format: freeform}
---

# Critical Instructions at Edges

Freeform instruction files must contain at least one directive instruction. Files without directives contribute no actionable guidance and cannot benefit from position-based ordering.

## Antipatterns

- **File with only informational prose.** A file containing project descriptions, reference tables, or background knowledge but no directive or constraint instructions has no content whose ordering matters. It fails the directive check.
- **File with only headings and code blocks.** Structural content like headings and fenced code examples are not directives. The file must contain at least one imperative or constraint instruction.
- **Relying on headings as instructions.** A heading like `## Testing` is organizational, not a directive. The file needs body-level instructions like "Run `pytest` before committing."

## Pass / Fail

### Pass

~~~~markdown
# Testing

Run `uv run pytest tests/` before committing changes.
*Do NOT skip the test suite for quick fixes.*
~~~~

### Fail

~~~~markdown
# Testing

The project uses pytest for testing.
Tests are located in the `tests/` directory.
~~~~

## Fix

Place critical instructions at the start of the first-loaded file or the end of the last-loaded file in the agent's loading order. If an instruction must appear in the middle, name specific constructs rather than using abstract terms.

## Limitations

Checks that the file contains directive instructions. Does not verify their position in the loading chain — position analysis is assessed separately.
