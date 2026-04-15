---
id: CORE:C:0005
slug: testing-framework-documented
title: "Testing Framework Documented"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {format: freeform}
---
# Testing Framework Documented

The instruction file must contain a heading matching testing terms (Testing, Tests, or Test). Documenting the testing framework tells the agent which tool to use, where tests live, and how to run them.

## Antipatterns

- Embedding test commands inline without a heading. Writing `uv run pytest` in a "Commands" section does not satisfy the check -- there must be a heading containing "Testing", "Tests", or "Test".
- Using a heading like "## Quality" or "## Validation" that covers testing but does not match the expected terms.
- Relying on the test runner's own documentation instead of including a testing section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Testing

Run `uv run pytest tests/ -v` for the full suite.
Test files use `test_` prefix with `pytest` fixtures.
~~~~

### Fail

~~~~markdown
# Project

## Commands

Run the linter and quality checks.
Make sure everything passes before committing.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
