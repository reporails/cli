---
id: CORE:C:0008
slug: validation-commands-present
title: "Validation Commands Present"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {format: freeform}
---
# Validation Commands Present

The instruction file must contain a heading matching validation terms (Validation, Verify, QA, Lint, or Check). Documenting validation commands tells the agent which quality gates to run before committing.

## Antipatterns

- Embedding lint commands in a "Commands" section without using a heading that matches validation terms. The check looks for headings containing Validation, Verify, QA, Lint, or Check.
- Using a heading like "## Build" that includes validation steps but does not match the expected terms.
- Listing validation tools in `pyproject.toml` without a corresponding section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## QA

Run `uv run poe qa_fast` for lint + type check.
Run `uv run poe qa` for the full suite.
~~~~

### Fail

~~~~markdown
# Project

## Setup

Install dependencies with `uv sync`.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
