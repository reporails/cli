# Architecture Principles

Foundational principles for all code in the reporails codebase.

## 1. DI-First + Import Purity

- Never construct heavy objects (HTTP clients, file handles, OpenGrep process) at import time
- All dependencies injected via function parameters
- Module imports must be side-effect free

## 2. Pure Decision Functions

- Isolate scoring, level determination, rule matching into pure functions
- Pure functions: same input → same output, no side effects
- Keep I/O separate from decision logic

## 3. Stateless Components

- All components (engine, scorer, formatters) are stateless
- No hidden mutable state on instances
- State flows through function parameters and return values

## 4. Structured Output via Dataclasses

- All data models defined as `@dataclass` (frozen where possible)
- Keep fields explicit — avoid `dict`, `Any`, `**kwargs`
- Validate at boundaries (user input, OpenGrep output, MCP responses)

## 5. Hexagonal Architecture (Ports & Adapters)

```
┌─────────────────────────────────────────┐
│              Interfaces                 │  ← Adapters (MCP, CLI)
├─────────────────────────────────────────┤
│                 Core                    │  ← Domain logic (pure)
├─────────────────────────────────────────┤
│              Formatters                 │  ← Adapters (output)
├─────────────────────────────────────────┤
│         External (OpenGrep, HTTP)       │  ← Adapters (infra)
└─────────────────────────────────────────┘
```

## 6. Formatter Interface

- Each output format implements the same interface:
  - `format_result(result: ValidationResult) -> T`
  - `format_score(result: ValidationResult) -> T`
  - `format_rule(rule_id: str, rule_data: dict) -> T`
- `json.py` is the canonical source; others may wrap it
- No business logic in formatters — pure transformation
- 