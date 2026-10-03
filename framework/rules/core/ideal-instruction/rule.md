---
id: CORE:C:0053
slug: ideal-instruction
title: "The Ideal Instruction"
category: coherence
type: mechanical
execution: server
severity: critical
match: {}
surface_mutations:
  memory: {applies: false}
---

# The Ideal Instruction

An instruction competes for attention against everything else in context. The strongest instructions dominate; weak instructions are effectively invisible.

Five properties determine instruction strength: specificity (name exact constructs), modality (use direct commands), elaboration (one compact sentence that names what it applies to, not a terse fragment), position (place critical instructions last), and topic relevance (instruction matches the task). They combine, but they are not the same kind of lever: specificity and elaboration do double duty — each strengthens the instruction and helps it stand out against competing same-topic content — while modality only sets how directly the command is phrased. Position lifts an abstract instruction; a named one is largely immune to it. The gap between a well-written and poorly-written instruction is enormous.

## Antipatterns

- **Hedged language**: "You might want to consider using `ruff` for formatting." Hedged modality weakens the instruction — direct commands ("Use `ruff` for formatting") are stronger.
- **Generic terms instead of named constructs**: "Use a linter for code quality" instead of "Use `ruff check` for linting." Specificity requires naming the exact tool, file, or command.
- **Naming what a prohibition forbids**: among other instructions on different topics, naming the forbidden tool can make the agent more likely to use it. Put a directive on the same topic that names the allowed tool, with its reason, just before the prohibition, or state the prohibition as a category.
- **Constraint-first ordering**: "Don't format files by hand. Use `ruff format` instead." Leading with the prohibition activates the wrong concept first. Directive-first ordering is more effective.
- **Terse instructions without elaboration**: "Format code." Too few words — the instruction lacks the detail needed to compete for attention in context.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff check --fix` for all linting in `src/` and `tests/`.
Run `pre-commit run --all-files` before every commit to keep the style consistent.
Format code with `ruff format`, because the CI style check runs it.
*Do not run any other formatter on files in this repository.*
~~~~

### Fail

~~~~markdown
You should probably consider formatting your code consistently.
~~~~

## Limitations

This is a composite diagnostic summarizing the overall strength of instructions in a file. Individual factors are reported by their own rules (specificity-gap, modality-weakness, etc.).
