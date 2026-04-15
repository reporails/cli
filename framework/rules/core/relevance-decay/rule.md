---
id: CORE:C:0045
slug: relevance-decay
title: "Relevance Decay"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
---

# Relevance Decay

Instructions are only effective for tasks they're semantically related to. A testing instruction has no effect on documentation tasks — the instruction must be relevant to the work at hand.

## Antipatterns

- **Mixing unrelated domains in one instruction.** Writing "Use `pytest` fixtures and keep documentation concise" tries to address two unrelated task types. Neither domain gets strong coverage because the instruction dilutes itself across contexts.
- **Generic instructions intended for all tasks.** Writing "be thorough and careful" has near-zero effect on any specific task. Domain-specific vocabulary is required for the instruction to activate during relevant work.
- **Assuming cross-domain transfer.** A testing-specific instruction like "always write edge-case tests" will not make the model more thorough when writing documentation. Each domain needs its own instructions.

## Pass / Fail

### Pass

~~~~markdown
# Testing

Run `uv run pytest tests/ -v` before committing.
Use `@pytest.mark.parametrize` for multiple input cases.

# Documentation

Write `docs/*.md` for people, not agents.
~~~~

### Fail

~~~~markdown
# Quality

Be thorough and careful in all tasks.
Always produce high-quality output.
Double-check your work.
~~~~

## Fix

If you need the same behavior across diverse task types, write separate versions of the instruction with domain-specific vocabulary for each. "Use `pytest` fixtures for test setup" only works for testing tasks — if you also want consistent patterns in scripts, write a separate instruction naming script-relevant constructs.

## Limitations

Measures semantic distance between instructions and task context. Cannot determine whether an instruction was intended to apply broadly or narrowly.
