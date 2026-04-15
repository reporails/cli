---
id: CORE:C:0033
slug: architecture-overview-present
title: "Architecture Overview Present"
category: coherence
type: mechanical
severity: high
backed_by: []
match: {type: main}
---
# Architecture Overview Present

The root instruction file must describe the project's architecture. The agent needs to know where major components live to navigate the codebase and make informed changes.

## Antipatterns

- Describing the architecture in prose paragraphs without a heading that contains "Architecture", "Structure", or "Layout". The check looks for a matching heading, not for architectural content buried in other sections.
- Using a heading like "## Overview" or "## Design" that does not contain any of the matched terms. Close synonyms do not satisfy the heading keyword check.
- Placing the architecture section in a separate file without any mention in the main instruction file. The check runs against the main file only.

## Pass / Fail

### Pass

~~~~markdown
# MyApp

Backend API for widget management.

## Architecture

src/ contains domain logic.
tests/ contains pytest suites.
~~~~

### Fail

~~~~markdown
# MyApp

Backend API for widget management.

## Commands

Run `make build` to compile.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
