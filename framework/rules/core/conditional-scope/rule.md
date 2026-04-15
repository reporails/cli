---
id: CORE:C:0048
slug: conditional-scope
title: "Conditional Scope"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
---

# Conditional Scope

Conditional instructions ("When X, do Y") are not uniformly weaker than unconditional ones. The "When X" scope text activates the model's knowledge about what's conventional in that domain. If the convention aligns with the instruction, the scope helps. If it conflicts, the scope actively hurts.

## Antipatterns

- Scoping an instruction to a domain where the opposite behavior is standard practice. "When writing API integrations, don't use mocks" fights the model's learned convention that API tests use mocks.
- Using a narrow scope clause that accidentally activates competing knowledge. "When building REST endpoints, avoid middleware" conflicts with the strong convention that REST APIs use middleware.
- Adding scope clauses to instructions that would be stronger without them. If the scope activates knowledge that conflicts with the directive, the unconditional version performs better.

## Pass / Fail

### Pass

~~~~markdown
When testing event-driven microservices, prefer
integration tests over mocks. Run the full service
with `docker compose up` before asserting.
~~~~

### Fail

~~~~markdown
When writing API integrations, never use mocks.
Always test against live endpoints regardless
of the development stage.
~~~~

## Fix

Use scope clauses that name domains where the desired behavior is standard practice — this can make the instruction MORE effective than having no scope at all. "When testing event-driven microservices" amplifies "don't mock" because integration testing IS the standard for microservices. Avoid scopes that name domains where the opposite behavior is standard ("API integrations" → mock). Broad scopes like "When writing tests" are safe — no penalty.

## Limitations

Evaluates scope-instruction alignment based on semantic similarity. Cannot determine real-world domain conventions — relies on the model's training distribution as a proxy.
