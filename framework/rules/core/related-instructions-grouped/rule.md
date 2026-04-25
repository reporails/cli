---
id: CORE:E:0005
slug: related-instructions-grouped
title: "Related Instructions Grouped"
category: efficiency
type: mechanical
severity: medium
backed_by:
- claude-md-guide
- spec-writing-for-agents
match: {format: freeform}
---
# Related Instructions Grouped

Related instructions must be grouped together, not scattered across the file. Co-location reduces the agent's search effort.

## Antipatterns

- **Flat file with no headings.** A long instruction file that lists directives without any section headings fails the structure check. The file must have at least 2 top-level headings to demonstrate topic grouping.
- **Single heading with all content underneath.** A file with one `# Title` heading and everything else in a single block is not organized into groups. The check requires at least 2 top-level headings (depth 1-2).
- **Using bold text instead of headings.** Formatting topic labels as `**Testing**` instead of `## Testing` does not create structural sections. The check evaluates heading-level organization.

## Pass / Fail

### Pass

~~~~markdown
# Testing

Run `uv run pytest tests/` before committing.

# Formatting

Use `ruff` for all formatting.
~~~~

### Fail

~~~~markdown
Run tests before committing.
Use ruff for formatting.
Keep files under 500 lines.
Check for type errors.
~~~~

## Limitations

Checks that the file uses headings to organize content. Does not evaluate whether the organization is logical or complete.
