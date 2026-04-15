---
id: CORE:E:0001
slug: total-instruction-size-limit
title: "Total Instruction Size Limit"
category: efficiency
type: mechanical
severity: high
backed_by: []
match: {format: freeform}
---

# Total Instruction Size Limit

The aggregate size of all instruction files in the project must not exceed 100 KB (102,400 bytes). Exceeding this limit wastes context budget and dilutes the effectiveness of individual instructions.

## Antipatterns

- Adding extensive documentation and examples to instruction files instead of keeping them concise. Instruction files should contain directives, not documentation.
- Duplicating instructions across multiple files. Each copy adds to the aggregate size without adding value.
- Including large code blocks or data tables in instruction files. Reference external files instead of embedding bulky content.
- Not monitoring total size as the project grows. Individual files may be small, but the aggregate can silently exceed the limit.

## Pass / Fail

### Pass

~~~~markdown
Project with 5 instruction files totaling 40 KB:
  CLAUDE.md (15 KB) + 4 scoped rules (6 KB each)
Total: 39 KB -- well under the 100 KB limit.
~~~~

### Fail

~~~~markdown
Project with 20 instruction files totaling 120 KB:
  CLAUDE.md (30 KB) + 19 scoped rules (5 KB each)
Total: 125 KB -- exceeds the 100 KB limit.
~~~~

## Limitations

Structural check with limited semantic understanding.
