---
id: CORE:C:0038
slug: instruction-rationale-present
title: "Instruction Rationale Present"
category: coherence
type: mechanical
severity: medium
match: {format: freeform}
---

# Instruction Rationale Present

The default pattern for instructions is a directive or imperative followed by brief context within a focused length. When you need to suppress a behavior, use the golden pattern: directive first, brief positive context, then constraint last. You don't need a constraint for every directive — add constraints only when your goal is to explicitly prevent something.

## Antipatterns

- **Pure constraint with no directive**: "*Do NOT use `black`.*" — a constraint without a preceding directive leaves the agent knowing what not to do but not what to do instead. The check requires directive atoms to be present.
- **All reasoning, no directive**: "The project uses consistent formatting because it reduces merge conflicts and improves readability." This is context without an actionable instruction. The check looks for directive/imperative atoms.
- **Directives buried in prose**: "It's worth noting that the team generally prefers using `ruff` for formatting tasks." Hedged language does not register as a directive atom — use imperative form ("Use `ruff` for formatting").

## Pass / Fail

### Pass

~~~~markdown
Use `ruff format` for all Python files in `src/` and `tests/`.
Consistent formatting reduces merge conflicts.
*Do NOT run `black` or apply manual formatting.*
~~~~

### Fail

~~~~markdown
The project values consistent code formatting across all
Python source files and test suites for better collaboration.
~~~~

## Fix

For directives and imperatives: state the instruction, add brief context if needed, keep it focused. For behavior suppression: directive ("Use `real_db` connections"), brief context about why, then constraint ("Do not use `unittest.mock`"). Do not mention the prohibited thing in the context — keep reasoning focused on the desired behavior.

## Limitations

Checks that the file contains directive instructions. Does not verify ordering or rationale placement — those are assessed separately.
