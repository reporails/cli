# Widget Service

A Python microservice for managing widget inventory.

## Commands

- `make build` — Build the Docker image
- `make test` — Run the test suite
- `make deploy` — Deploy to staging

## Architecture

Layered architecture with separate API, service, and repository layers.

## Constraints

- MUST validate all API inputs
- NEVER expose internal IDs in responses
- MUST log all state mutations
- NEVER commit secrets or API keys
