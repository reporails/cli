---
id: CORE:D:0003
slug: instruction-ordering
title: "Instruction Ordering"
category: direction
type: mechanical
execution: server
severity: high
match: {}
surface_mutations:
  memory: {applies: false}
---

# Instruction Ordering

Within a topic, the ORDER of instructions matters. Putting the directive first, reasoning between, and the constraint last is significantly more effective than the natural human pattern of leading with prohibitions.

## Antipatterns

- **Constraint-first pattern**: "Don't use `black`. Use `ruff format` instead." Leading with the prohibition activates the forbidden concept before the desired behavior is established. The diagnostic detects this inverted ordering.
- **Reasoning before directive**: "Because mock objects hide integration bugs, use real database connections." The reason is stated before the instruction — the directive should come first so the agent knows what to do before learning why.
- **Interleaved ordering**: "Don't use mocks. Real tests catch more bugs. Use `pytest` with real connections. Never stub HTTP calls." Alternating between directives and constraints within a topic makes both weaker.

## Pass / Fail

### Pass

~~~~markdown
Use `pytest` with real database connections for integration tests.
Real integration tests catch deployment failures before they reach production.
*Do not use mocking libraries or test doubles for service boundaries.*
~~~~

### Fail

~~~~markdown
# Shell Commands

This project runs its test suite and deploy scripts through subprocess calls.

*Do not use `subprocess.run` with `shell=True`.*
Use `subprocess.run` with `shell=False`.

Document any new script in `docs/scripts.md`.
~~~~

## Limitations

Fires on a prohibition that comes before every directive on its topic. A directive and a prohibition on one subject but worded very differently may not be recognized as one topic. Order inside one sentence is not checked, and what the reasoning between a directive and its prohibition says is covered by The Ideal Instruction (`CORE:C:0053`).
