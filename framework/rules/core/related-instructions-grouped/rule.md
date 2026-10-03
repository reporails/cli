---
id: CORE:E:0005
slug: related-instructions-grouped
title: "Related Instructions Grouped"
category: efficiency
type: mechanical
severity: low
depends_on: [CORE:S:0016]
backed_by:
- claude-md-guide
- spec-writing-for-agents
match: {type: [main, override, agents_md, legacy_cursorrules, cross_read, system_prompt], cardinality: [singleton, chain]}
---
# Related Instructions Grouped

The agent's main instruction file must group related instructions by topic into their own sections, rather than scattering a topic's directives across the file — grouping by topic keeps each directive near the context that makes it relevant. But grouping is not cramming: directives packed tightly together compete hardest for attention, since the closer two directives sit the more they draw from the same share. Group BY TOPIC; do not simply co-locate everything.

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
