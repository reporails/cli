---
id: CORE:E:0004
slug: instruction-elaboration
title: "Instruction Elaboration"
category: efficiency
type: mechanical
execution: server
severity: high
match: {}
fix: |
  Expand the instruction to 15-50 distinct tokens. Add the conditions
  under which it applies, the specific tool / file / command involved,
  and one concrete example. "Test the code" → "Run \`pytest tests/\`
  with the \`-v\` flag before each \`git commit\` so failures surface
  inline." Too-short instructions lack tokens the model can activate on.
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
*Do not rely on mocking libraries or test doubles.*
~~~~

### Fail

~~~~markdown
Run tests.
~~~~

## Fix

Elaborate directives with multiple specific, diverse terms, each naming a different concrete aspect: `pytest`, `@pytest.mark.parametrize`, `tests/unit/`, real database connections, real HTTP endpoints. Naming strengthens a directive you want the model to follow. Prohibitions are the inverse: state the forbidden thing as an abstract category rather than a named construct, because naming a prohibited API anchors the forbidden concept instead of suppressing it. *Do not pad with generic filler.* Phrases like "when writing tests in this project, please ensure that you avoid using" dilute the signal without adding distinct terms.

## Limitations

Measures token count and term distinctness. Cannot evaluate whether the chosen terms are the most relevant for the intended behavior.
