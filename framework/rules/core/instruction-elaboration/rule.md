---
id: CORE:E:0004
slug: instruction-elaboration
title: "Instruction Elaboration"
category: efficiency
type: mechanical
execution: server
severity: high
match: {}
---

# Instruction Elaboration

Instructions with too few tokens are effectively invisible. Instructions padded with generic filler are weaker than shorter, specific ones. The ideal instruction uses multiple DISTINCT relevant terms — each naming a different concrete aspect of the desired behavior.

## Antipatterns

- **Terse instruction**: "Format code." or "Run tests." — too few distinct tokens to register in context. The diagnostic flags instructions below the minimum token count.
- **Padded with filler**: "When writing tests in this project's codebase, please ensure that you avoid using mock objects." The filler tokens ("when writing", "please ensure that you") dilute signal without adding distinct terms.
- **Repetitive terms instead of diverse ones**: "Use `ruff` for linting. `ruff` catches errors. `ruff` runs fast." Repeating the same term does not increase distinctness — the diagnostic measures unique relevant terms, not total word count.
- **Generic class names instead of specifics**: "Use a testing framework" instead of "Use `pytest` with `@pytest.mark.parametrize` for boundary cases in `tests/`." Named constructs are distinct terms; generic descriptions are not.

## Pass / Fail

### Pass

~~~~markdown
Use `pytest` with `@pytest.mark.parametrize` for boundary cases in
`tests/unit/`. Run `uv run poe qa_fast` before committing.
*Do NOT use `unittest.mock` or `MagicMock`.*
~~~~

### Fail

~~~~markdown
Run tests.
~~~~

## Fix

Elaborate instructions with multiple specific, diverse terms — each naming a different concrete aspect. "Do not use `unittest.mock`, `MagicMock`, `@patch`, or any test double for external service boundaries. Test against real implementations — real database connections, real HTTP endpoints, real queue consumers." Each named construct strengthens the instruction independently. Do NOT pad with generic filler: "when writing tests in this project's codebase, please ensure that you avoid using..." — filler tokens dilute without strengthening.

## Limitations

Measures token count and term distinctness. Cannot evaluate whether the chosen terms are the most relevant for the intended behavior.
