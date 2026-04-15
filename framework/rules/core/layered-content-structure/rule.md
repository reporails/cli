---
id: CORE:S:0016
slug: layered-content-structure
title: "Layered Content Structure"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {format: freeform}
---
# Layered Content Structure

Instruction content must be organized with at least two top-level headings for major topics. This lets the agent quickly find relevant sections instead of scanning a flat wall of text.

## Antipatterns

- **Single heading followed by all content**: A file with only `# Project` and then 200 lines of mixed instructions. The check requires at least 2 headings to confirm layered structure.
- **Headings only at deep levels**: Using `###` and `####` without any `#` or `##` headings. The check looks for top-level heading structure, not deeply nested subsections.
- **No headings at all**: A freeform file with paragraphs but no markdown headings. The check requires headings to be present as structural markers.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup
Install dependencies with `uv sync`.

## Commands
Run `uv run ails check .` to validate.
~~~~

### Fail

~~~~markdown
Install dependencies with `uv sync`.
Run `uv run ails check .` to validate.
Use `ruff` for formatting.
~~~~

## Limitations

Checks that the file uses headings to organize content. Does not evaluate whether the organization is logical or complete.
