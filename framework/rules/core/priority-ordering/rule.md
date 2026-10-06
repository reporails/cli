---
id: CORE:C:0036
slug: priority-ordering
title: Critical Instructions at Edges
category: coherence
type: mechanical
severity: medium
depends_on: [CORE:D:0001]
backed_by: [builder-ai-instruction-best-practices, claude-md-guide, claudemd-best-practices-mermaid-for-workflows,
  enterprise-claude-usage, fowler-context-engineering-agents, instruction-limits-principles,
  lost-in-the-middle-long-contexts, rules-directory-mechanics, sewell-agents-md-tips,
  spec-writing-for-agents]
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
*Do not skip the test suite for quick fixes.*
~~~~

### Fail

~~~~markdown
# Testing

The project uses pytest for testing.
Tests are located in the `tests/` directory.
~~~~

## Limitations

Checks that the file contains directive instructions. Does not verify their position in the loading chain — position analysis is assessed separately.
