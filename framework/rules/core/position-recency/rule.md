---
id: CORE:C:0047
slug: position-recency
title: "Position Recency"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Position Recency

Instructions at the end of a multi-instruction context dominate. Instructions at the beginning are dramatically weak.

## Antipatterns

- **Placing critical constraints at the top of the file.** A "NEVER delete production data" instruction at line 1 is in the weakest position. Later instructions on unrelated topics will dominate, and the constraint may be ignored.
- **Burying critical instructions in the middle.** An important directive sandwiched between boilerplate sections gets minimal attention from the model. Middle positions are weaker than both the beginning and the end.
- **Relying on emphasis alone.** Bold text or uppercase ("**IMPORTANT**") does not compensate for weak position. A normal instruction at the end outperforms an emphasized instruction at the beginning.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

Use `uv sync` to install dependencies.

# Constraints

*NEVER modify `.env` files directly.*
~~~~

### Fail

~~~~markdown
# Constraints

*NEVER modify `.env` files directly.*

# Project Setup

Use `uv sync` to install dependencies.
Run `uv run poe qa` for testing.
~~~~

## Fix

Place highest-priority instructions LAST. Moving a critical instruction from the beginning to the end of a file dramatically increases compliance. For conflicting instructions, the last one wins — reorder or remove the conflict.

## Limitations

Evaluates position of abstract (non-named) instructions. Named instructions are not penalized for position — specificity overrides position effects.
