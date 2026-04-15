---
id: CORE:C:0022
slug: safety-gate-directives
title: "Safety Gate Directives"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {format: freeform}
---
# Safety Gate Directives

The instruction file must contain constraint atoms -- safety directives using keywords like NEVER, MUST NOT, or ALWAYS. Without hard boundaries, the agent has no guardrails for dangerous operations.

## Antipatterns

- Writing soft suggestions ("try to avoid deleting files") instead of hard constraints (`NEVER delete files without confirmation`). Soft language does not register as a constraint atom.
- Placing all safety guidance in external documentation instead of in the instruction file. The check looks for constraint atoms in the file's content.
- Using positive-only instructions with no boundaries. A file full of "do X" directives with no "NEVER do Y" constraints passes the directive check but fails the safety gate check.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Boundaries

NEVER modify `.env` files directly.
ALWAYS run `uv run poe qa` before committing.
~~~~

### Fail

~~~~markdown
# Project

## Guidelines

Try to be careful with environment files.
It would be good to run tests before committing.
~~~~

## Limitations

Uses content analysis on mapped instruction atoms. Results depend on mapper quality and may miss edge cases.
