---
id: CORE:E:0003
slug: formatting-regime
title: "Formatting Effectiveness"
category: efficiency
type: mechanical
execution: server
severity: low
match: {}
surface_mutations:
  memory: {applies: false}
  config: {applies: false}
---

# Formatting Effectiveness

Use `backtick` for code identifiers whether the sentence is a directive or a prohibition. Bold draws the model's attention to the wrapped term. Inside a prohibition, that spotlights the forbidden concept — the opposite of what you want — so carry the constraint in *italic* instead. On a positive directive, bold spotlights the behaviour you DO want, so it is not penalized.

Bold on structural labels (`**G1 Schema**:`, `**Agent 1**:`) is allowed — these are organizational markers followed by `:`, not emphasis on constraint terms. The label pattern identifies content structure, not prohibited concepts.

## Antipatterns

- **Bold on prohibited terms** like "NEVER use **eval** in production code". Bold amplifies the prohibited concept instead of suppressing it. State the prohibition as an abstract category in plain *italic* text rather than naming the forbidden construct.
- **Bold for emphasis on constraints** like "Do **not** modify the database" — bold on negation keywords competes with the instruction's intent. Use *italic* for the full constraint sentence.
Bold inside a positive directive (`ALWAYS run **ruff**`) is not an antipattern — there bold highlights the behaviour you want. Prefer `ruff` in backticks for the code construct itself, but the check does not flag it.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for formatting and linting.
*Do not run a formatter other than `ruff`.*
**Always** run tests before committing.
**G1 Schema**: `id` must match the coordinate pattern.
~~~~

### Fail

~~~~markdown
NEVER use **black** for formatting.
Do **not** modify the **database** directly.
~~~~

## Limitations

Fires on `**bold**` inside prohibitions, where bold amplifies the forbidden concept. Bold inside positive directives is not flagged — there it highlights the desired behaviour. Skips bold spans followed by `:` (structural labels). Does not check whether the specific bolded token is the forbidden concept versus another word in the prohibition.
