---
id: CORE:C:0041
slug: content-dilution
title: "Content Dilution"
category: coherence
type: mechanical
execution: server
severity: low
match: {}
---

# Content Dilution

Same-topic prose can compete with your instruction on that topic: prose and directive share the attention that topic draws, so descriptive same-topic content can pull attention away from the directive. A little context costs little; large volumes can pull enough away to blunt the instruction.

Off-topic content is not free either. A single off-topic span is nearly invisible, but off-topic volume accumulates — on a large file the piled-up off-topic mass can crowd the whole surface and thin every instruction's share of attention. Small off-topic context is harmless; large off-topic volume is not.

Vague instructions are especially vulnerable — instructions that name specific constructs resist this competition much better.

## Antipatterns

- Writing a paragraph of background context directly before or after an instruction on the same topic. On-topic prose can compete for attention and can dilute the instruction's effect.
- Embedding a single directive inside a long explanatory section. The instruction can drown in surrounding prose even if the prose is accurate and helpful.
- Adding extensive rationale after every instruction. One to three sentences of rationale is fine; multiple paragraphs shifts the balance from directive to descriptive.

## Pass / Fail

### Pass

~~~~markdown
## Formatting

Use `ruff` for all formatting. The project enforces
consistent style across `src/` and `tests/`.
Never run a formatter other than `ruff`.
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

## Limitations

Detects prose volume relative to instruction density within topic clusters. Cannot evaluate whether the prose is genuinely helpful context or unnecessary padding.

How much same-topic prose weakens an instruction depends on the model. Treat the finding as a prompt to review the prose, not as an instruction to delete it.
