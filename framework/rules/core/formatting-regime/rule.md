---
id: CORE:E:0003
slug: formatting-regime
title: "Formatting Effectiveness"
category: efficiency
type: mechanical
execution: server
severity: low
match: {}
---

# Formatting Effectiveness

Use `backtick` for code identifiers and *italic* for emphasis instead of `**bold**` on terms inside constraints. Bold draws the model's attention to the wrapped term — on a constraint, that means drawing attention to the prohibited concept.

Bold on structural labels (`**G1 Schema**:`, `**Agent 1**:`) is allowed — these are organizational markers followed by `:`, not emphasis on constraint terms. The label pattern identifies content structure, not prohibited concepts.

## Antipatterns

- **Bold on prohibited terms** like "NEVER use **eval** in production code" — bold on `eval` amplifies the prohibited concept instead of suppressing it. Use `eval` (backtick) instead.
- **Bold for emphasis on constraints** like "Do **not** modify the database" — bold on negation keywords competes with the instruction's intent. Use *italic* for the full constraint sentence.
- **Bold inside NEVER/ALWAYS sentences** like "ALWAYS use **ruff** for formatting" — bold on the tool name creates salience competition. Use `ruff` (backtick) for code constructs.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for formatting and linting.
*Do NOT run `black` or manual formatting.*
**G1 Schema**: `id` must match the coordinate pattern.
~~~~

### Fail

~~~~markdown
NEVER use **black** for formatting.
Do **not** modify the **database** directly.
**Always** run tests before committing.
~~~~

## Limitations

Detects bold formatting on charged atoms. Skips bold spans followed by `:` (structural labels). Does not evaluate whether the bolded terms are the prohibited concepts or the negation keywords.
