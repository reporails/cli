---
id: CORE:C:0010
slug: build-and-test-commands
title: "Build And Test Commands"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {type: main}
---
# Build And Test Commands

The instruction file must include build and test commands that the agent can run. Without these, the agent can't verify its own changes work correctly.

## Antipatterns

- Providing build commands in prose ("you can build by running the makefile") without a heading containing "Commands", "Build", "Testing", or "Setup". The check matches headings, not body text.
- Using a heading like "## Development" or "## Usage" that does not contain any of the matched terms. The heading must include one of the specific keywords.
- Documenting commands only in a README or separate file. The check targets the main instruction file.

## Pass / Fail

### Pass

~~~~markdown
# MyProject

## Commands

- `npm install` -- install dependencies
- `npm test` -- run test suite
~~~~

### Fail

~~~~markdown
# MyProject

## Conventions

Use ESLint for linting.
Prefer functional components.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
