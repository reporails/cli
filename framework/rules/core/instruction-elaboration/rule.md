---
id: CORE:E:0004
slug: instruction-elaboration
title: "Instruction Elaboration"
category: efficiency
type: mechanical
execution: server
severity: low
match: {}
---

# Instruction Elaboration

Instructions with too few words are effectively invisible. The strongest instruction is one compact sentence that names the specific tool, file, or command it applies to.

## Antipatterns

- **Terse instruction**: "Format code." or "Run tests." — too few words to register in context. The diagnostic flags instructions at or below the minimum token count.
- **One instruction split into fragments**: "Use `ruff` for linting. `ruff` catches errors. `ruff` runs fast." Three short sentences say one thing, and each is too brief to register on its own. Fold them into one sentence that says what `ruff` is for and when to run it.
- **Generic class names instead of specifics**: "Use a testing framework" instead of "Use `pytest` with `@pytest.mark.parametrize` for boundary cases in `tests/`." Named constructs are distinct terms; generic descriptions are not.

## Pass / Fail

### Pass

~~~~markdown
Use `pytest` with `@pytest.mark.parametrize` to cover each boundary case of a function.
Run `uv run poe qa_fast` to lint, type-check and test the code in one command.
*Do not rely on `unittest.mock` or other test doubles to stand in for real objects.*
~~~~

### Fail

~~~~markdown
Run tests.
~~~~

## Limitations

Measures token count only; the tokens inside a backtick-wrapped span are counted like any others. Cannot evaluate whether the chosen words are the most relevant for the intended behavior. It reads one instruction at a time: fragments of one instruction fold into one sentence, while a sentence that gives two instructions is split into two by One Instruction Per Sentence (CORE:C:0058).
