# Platform Service

A governed Python service with full structure.

## Session Start

1. Read `.reporails/backbone.yml`
2. Check project status

## Commands

- `make build` — Build the service
- `make test` — Run full test suite
- `make deploy` — Deploy to staging

## Architecture

See component documentation in `.claude/rules/`.

## Constraints

- MUST validate all inputs at boundaries
- NEVER push directly to main
- MUST write tests for all new features
- NEVER log secrets or credentials
