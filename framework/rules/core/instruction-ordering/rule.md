---
id: CORE:D:0003
slug: instruction-ordering
title: "Instruction Ordering"
category: direction
type: mechanical
execution: server
severity: high
match: {}
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
Real integration tests catch deployment failures that mocks hide.
*Do NOT use `unittest.mock` or test doubles for service boundaries.*
~~~~

### Fail

~~~~markdown
Don't use mock objects or test doubles. They hide integration bugs.
Use real database connections instead.
~~~~

## Fix

Restructure instructions as:
```
[DIRECTIVE] Use real implementations — real database connections, real HTTP endpoints.
[REASONING] Real integration tests catch deployment failures and configuration
errors that would otherwise reach production undetected.
[CONSTRAINT] Do not use mock objects, stubs, or test doubles.
```

Never write "Don't use X. Instead, use Y." Write "Use Y. [reason for Y]. Don't use X."
Reasoning should support the directive, not explain what's wrong with the prohibited thing.

## Limitations

Detects ordering patterns within instruction clusters. Cannot evaluate whether the reasoning content actually supports the directive.
