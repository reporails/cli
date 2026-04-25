---
id: CORE:E:0006
slug: italic-constraints
title: "Italic Constraints"
category: efficiency
type: mechanical
severity: medium
match: {}
---

# Italic Constraints

Constraint instructions (-1 charge) should be wrapped entirely in `*italic*` markdown. Full-sentence italic signals the charge type visually, separating the constraint from the directive (+1) and reasoning (0) that precede it.

## Antipatterns

- **Partial italic on negation only**: "*Do NOT* modify `checks.yml` directly." — only the negation keyword is italicized, not the full constraint sentence. The check requires the entire constraint atom to be wrapped in `*...*`.
- **Bold instead of italic**: "**Do NOT modify checks.yml directly.**" — bold is not the same signal as italic. The check looks for single `*...*` markers, not `**...**`.
- **No formatting on constraint**: "Do NOT modify checks.yml directly." — an unformatted constraint is structurally indistinguishable from surrounding prose. The check flags constraint atoms whose raw text lacks full italic wrapping.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for all formatting in `src/`.
*Do NOT run `black` or apply manual formatting.*
~~~~

### Fail

~~~~markdown
Use `ruff` for all formatting in `src/`.
Do NOT run `black` or apply manual formatting.
~~~~

## Fix

Wrap the entire constraint sentence in `*...*`: write `*Do NOT modify checks.yml directly.*` not `Do NOT modify checks.yml directly.` and not `*Do NOT* modify checks.yml directly.` — partial italic on just the negation keyword activates the prohibited concept without the charge signal.

## Limitations

Detects constraint atoms (charge == -1) whose raw markdown text is not fully wrapped in single `*...*` markers. Does not evaluate whether the italic wrapping improves compliance for the specific instruction — the check is structural, not semantic.
