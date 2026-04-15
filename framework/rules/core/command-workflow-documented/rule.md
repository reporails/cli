---
id: CORE:C:0021
slug: command-workflow-documented
title: "Command Workflow Documented"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {format: freeform}
---
# Command Workflow Documented

The instruction file must document command workflows — ordered sequences of steps for common operations like building, testing, and deploying.

## Antipatterns

- Listing individual commands without a heading containing "Workflow", "Process", or "Pipeline". The check matches headings, not command content in other sections.
- Using a heading like "## Steps" or "## Procedures" that does not include any matched keyword. The heading must contain one of the specific terms.
- Documenting workflows only in a CI config file (`.github/workflows/`) without a corresponding section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# MyProject

## Workflow

1. Run `uv sync` to install dependencies
2. Run `uv run poe qa` to validate
3. Commit with a descriptive message
~~~~

### Fail

~~~~markdown
# MyProject

## Commands

- `uv sync`
- `uv run poe qa`
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
