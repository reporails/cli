---
id: CORE:C:0053
slug: ideal-instruction
title: "The Ideal Instruction"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
---

# The Ideal Instruction

An instruction competes for attention against everything else in context. The strongest instructions dominate; weak instructions are effectively invisible.

Five properties determine instruction strength (they multiply): specificity (name exact constructs), modality (use direct commands), elaboration (15-50 distinct terms), position (place critical instructions last), and topic relevance (instruction matches the task). The gap between a well-written and poorly-written instruction is enormous.

## Antipatterns

- **Hedged language**: "You might want to consider using `ruff` for formatting." Hedged modality weakens the instruction — direct commands ("Use `ruff` for formatting") are stronger.
- **Generic terms instead of named constructs**: "Use a linter for code quality" instead of "Use `ruff check` for linting." Specificity requires naming the exact tool, file, or command.
- **Constraint-first ordering**: "Don't use `black`. Use `ruff` instead." Leading with the prohibition activates the wrong concept first. Directive-first ordering is more effective.
- **Terse instructions without elaboration**: "Format code." Too few distinct tokens — the instruction lacks the detail needed to compete for attention in context.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff check --fix` for all linting in `src/` and `tests/`. The project
enforces consistent style through pre-commit hooks. *Do NOT run `black`
or apply manual formatting.*
~~~~

### Fail

~~~~markdown
You should probably consider formatting your code consistently.
~~~~

## Fix

1. Elaborate with distinct relevant terms — the single largest improvement factor
2. Use exact names — `unittest.mock`, not "mocking libraries"
3. Order: directive first, reasoning, constraint last
4. Place critical instructions last in the file
5. Use direct commands, not hedged language
6. One instruction per topic (eliminates same-topic competition)
7. Keep surrounding same-topic prose brief (reduces attention dilution)

## Limitations

This is a composite diagnostic summarizing the overall strength of instructions in a file. Individual factors are reported by their own rules (specificity-gap, modality-weakness, etc.).
