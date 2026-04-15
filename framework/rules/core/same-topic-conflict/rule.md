---
id: CORE:C:0046
slug: same-topic-conflict
title: "Same-Topic Reinforcement and Conflict"
category: coherence
type: mechanical
execution: server
severity: critical
match: {}
---

# Same-Topic Reinforcement and Conflict

Multiple instructions on the same topic must agree in direction. Conflicting instructions on the same topic destroy compliance catastrophically -- the model cannot follow both and may follow neither.

## Antipatterns

- Writing "Use `ruff` for formatting" in one file and "Use `black` for formatting" in another. Same topic, opposite directives -- the model picks one unpredictably.
- Adding nuanced exceptions without scoping them: "ALWAYS use `pytest`" alongside "Don't use `pytest` for integration tests" reads as a contradiction without explicit conditional scoping.
- Restating a directive with weaker language elsewhere. "NEVER push to `main`" in one file and "Avoid pushing to `main`" in another creates ambiguity about whether the constraint is absolute.

## Pass / Fail

### Pass

~~~~markdown
<!-- file: .claude/rules/testing.md -->
Use `pytest` for all test files in `tests/`.
Run `uv run pytest tests/ -v` before committing.
~~~~

### Fail

~~~~markdown
<!-- file: .claude/rules/testing.md -->
Use `pytest` for all tests.
<!-- file: .claude/rules/workflow.md -->
Use `unittest` for all tests.
~~~~

## Fix

Remove or resolve conflicts first. Then check for weak reinforcement: strengthen the weak instruction (name constructs, use imperative modality) or remove it. Reinforce only with instructions of comparable strength.

## Limitations

Detects same-topic instruction pairs using embedding similarity and opposite direction. May flag intentional nuance (e.g., "prefer X" with "but use Y when Z") as a conflict when the instructions are meant to coexist with different scopes.
