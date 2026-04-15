---
id: CORE:C:0042
slug: specificity-gap
title: "Specificity Gap"
category: coherence
type: mechanical
execution: server
severity: critical
match: {}
---

# Specificity Gap

Instructions must name concrete constructs -- backtick-wrapped tokens, file paths, function names, CLI commands -- instead of abstract concepts. Abstract instructions are dramatically less effective because the model cannot distinguish them from general knowledge.

## Antipatterns

- Writing "Follow the coding style" instead of naming the specific tool (`ruff format`, 4-space indent, `snake_case`). The model interprets abstract style references using its own defaults.
- Using category names like "mocking libraries" instead of specific imports like `unittest.mock`, `MagicMock`, `patch()`. Category names are as vague as abstract concepts.
- Stating "Run the tests" without specifying the command (`uv run pytest tests/ -v`). The model guesses which test runner to use.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff format` with 4-space indent and `snake_case`
for all functions in `src/reporails_cli/`.
Run `uv run pytest tests/ -v` before committing.
~~~~

### Fail

~~~~markdown
Follow the project's coding style.
Run the tests before committing.
Use appropriate mocking libraries.
~~~~

## Fix

Replace "Don't use mocking" with "Don't use `unittest.mock`,
`MagicMock`, `patch()`". Replace "Follow the coding style" with "Use `ruff format`,
4-space indent, `snake_case` for functions". Name the exact tools, functions, files,
patterns, and libraries. Category names ("mocking libraries") are as vague as
abstract concepts — the model needs the import path, not the category.

## Limitations

Measures whether instructions contain named constructs (backtick-wrapped tokens, file paths, function names). Cannot evaluate whether the named constructs are the right ones for the project.
