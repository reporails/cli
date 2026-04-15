---
id: CORE:C:0011
slug: security-requirements
title: "Security Requirements"
category: coherence
type: mechanical
severity: high
backed_by: []
match: {format: freeform}
---
# Security Requirements

The instruction file must contain a section with a heading matching security-related terms (Security, Boundaries, Sensitive, or Access). Without documented security requirements, the agent has no guidance on sensitive files, access restrictions, or security patterns.

## Antipatterns

- Embedding security constraints inline without a dedicated heading. The check looks for a heading containing terms like "Security" or "Boundaries" -- scattered constraints without a heading section are not detected.
- Using a heading like "Important Notes" that contains security content but does not match any of the expected terms. The heading must include Security, Boundaries, Sensitive, or Access.
- Documenting security requirements only in external files (e.g., a `SECURITY.md`) that are not instruction files. The check applies to instruction files the agent reads at session start.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Boundaries

NEVER modify `.env` or `credentials.json`.
Ask the user to handle sensitive file changes manually.
~~~~

### Fail

~~~~markdown
# Project

## Commands

Run `uv run poe qa` before committing.
Be careful with environment files.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
