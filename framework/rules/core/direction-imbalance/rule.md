---
id: CORE:D:0002
slug: direction-imbalance
title: "Direction Imbalance"
category: direction
type: mechanical
execution: server
severity: medium
match: {}
fix: |
  Add a directive (+1) before the constraint (-1) on the same topic.
  Pattern: directive → reasoning → constraint. "Run \`pytest\` before
  each commit. Tests catch regressions early. *Do not skip tests when
  the CI is red.*" The model follows the last-seen instruction on a
  topic; constraint-first means the directive never lands.
---

# Direction Imbalance

Directives and constraints within the same topic must have balanced strength. When prohibitions are written more strongly than enabling instructions, the agent may suppress the intended behavior entirely rather than conditionally gating it.

## Antipatterns

- **Strong constraint, weak enabler** like "NEVER push to remote" paired with "you can push if asked" — the absolute prohibition overwhelms the hedged permission, producing "never push" regardless of context.
- **Specific constraint, vague enabler** like "NEVER modify `src/pipeline.py`" paired with "make changes when appropriate" — the named construct in the constraint anchors harder than the abstract enabler.
- **Multiple reinforcing constraints, single enabler** like three variations of "do not commit" followed by one "commit when asked" — repetition amplifies the constraint side.

## Pass / Fail

### Pass

~~~~markdown
Run `uv run pytest tests/` before submitting changes. Verify all tests pass.
*Do NOT skip the test suite or push with failing tests.*
~~~~

### Fail

~~~~markdown
You might want to run tests if you have time.
NEVER skip tests. NEVER push without testing. NEVER submit untested code.
~~~~

## Fix

Match instruction strength to behavioral intent. If the intended behavior is "X then Y" (sequential), make sure both sides are equally strong:
- Make the enabling instruction imperative, not conditional ("State your conclusion" not "When done, stop")
- Make the enabling instruction name specific constructs ("implementation file" not "verified facts")
- Add reinforcing instructions for the weaker side if needed

## Limitations

Detects strength imbalance between opposing instructions within a topic. Cannot determine behavioral intent — only flags disproportionate strength ratios.
