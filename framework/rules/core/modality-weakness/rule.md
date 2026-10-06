---
id: CORE:C:0043
slug: modality-weakness
title: "Modality Weakness"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Modality Weakness

Hedged instructions ("should", "try to", "consider", "prefer") couple significantly weaker than direct instructions ("do not", bare imperatives).

## Antipatterns

- Writing "You should run tests before merging" instead of "Run tests before merging" -- hedged modality reduces compliance compared to direct imperatives.
- Using "Consider using `ruff` for formatting" when the intent is mandatory -- "consider" signals optional guidance, so the agent may skip it entirely.
- Prefixing constraints with "Try to avoid" instead of "Do not" -- the softer phrasing undercuts the constraint's force.
- Reserving hedges like "prefer" for hard requirements -- "Prefer X over Y" reads as a suggestion, not a mandate.

## Pass / Fail

### Pass

~~~~markdown
Run `uv run pytest` before every commit.
Use `ruff` for formatting.
Do not modify generated files in `dist/`.
~~~~

### Fail

~~~~markdown
You should run tests before merging.
Consider using `ruff` for formatting.
Try to avoid modifying generated files.
~~~~

## Limitations

Detects hedged modality markers ("should", "try to", "consider", "prefer") in instructions. Some hedging is intentional for truly optional guidance — this diagnostic flags all hedging regardless of intent.
