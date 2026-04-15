---
id: CORE:C:0041
slug: content-dilution
title: "Content Dilution"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Content Dilution

Descriptive prose on the same topic as your instructions competes for attention. Small amounts of context help, but large amounts dilute the instruction's effect. Off-topic content is harmless regardless of volume.

Vague instructions are especially vulnerable — instructions that name specific constructs resist prose competition much better.

## Antipatterns

- Writing a paragraph of background context directly before or after an instruction on the same topic. On-topic prose competes for attention and dilutes the instruction's effect.
- Embedding a single directive inside a long explanatory section. The instruction drowns in surrounding prose even if the prose is accurate and helpful.
- Adding extensive rationale after every instruction. One to three sentences of rationale is fine; multiple paragraphs shifts the balance from directive to descriptive.

## Pass / Fail

### Pass

~~~~markdown
## Formatting

Use `ruff` for all formatting. The project enforces
consistent style across `src/` and `tests/`.
NEVER run `black` or manual formatting.
~~~~

### Fail

~~~~markdown
## Formatting

Code formatting is essential for maintaining readability
across a team. There are many tools available for Python
formatting including black, autopep8, yapf, and ruff.
Each has tradeoffs in speed, configurability, and
community adoption. Use `ruff` for formatting.
~~~~

## Fix

Separate instructions from on-topic prose. Move descriptions, context, and explanations to separate sections or files. Keep the area around instructions clean — 1-3 sentences of rationale, not paragraphs of background.

## Limitations

Detects prose volume relative to instruction density within topic clusters. Cannot evaluate whether the prose is genuinely helpful context or unnecessary padding.
