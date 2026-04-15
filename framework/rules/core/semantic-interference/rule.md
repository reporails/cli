---
id: CORE:C:0049
slug: semantic-interference
title: "Scope-Instruction Conflict"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Scope-Instruction Conflict

Conditional scopes must not name domains whose conventions contradict the instruction. A scope that activates domain knowledge conflicting with the directive makes the instruction less effective than having no scope at all.

## Antipatterns

- Writing "When testing API integrations, don't use mocks" -- API integration testing conventionally uses mocks, so the scope activates knowledge that opposes the directive.
- Scoping a constraint to a domain where the prohibited behavior is standard practice. "In React components, avoid using state" activates the model's knowledge that React components routinely use state.
- Using broad domain scopes that trigger multiple competing conventions. "When writing Python, NEVER use list comprehensions" fights the model's strong association between Python and comprehensions.

## Pass / Fail

### Pass

~~~~markdown
When testing event-driven microservices, don't mock
service calls -- use real service instances.
~~~~

### Fail

~~~~markdown
When testing API integrations, don't use mocks.
~~~~

## Fix

When writing conditional instructions that suppress a behavior, ensure the scope names a domain where the DESIRED behavior is conventional. "When testing API integrations, don't mock" is self-defeating because API integration testing conventionally USES mocks. "When testing event-driven microservices, don't mock" reinforces because microservice testing conventionally uses real services. Choose domain scopes where the desired behavior aligns with the domain's conventions.

## Limitations

Detects misalignment between scope text and instruction direction. Relies on semantic similarity as a proxy for domain conventions — may flag scopes that are unconventional but intentional.
