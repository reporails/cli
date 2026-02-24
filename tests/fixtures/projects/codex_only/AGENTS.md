# Inventory API

A Node.js REST API for inventory management.

## Commands

- `npm run build` — Build the project
- `npm test` — Run the test suite
- `npm run lint` — Run linter

## Architecture

Express-based REST API with PostgreSQL database and Redis caching layer.

## Constraints

- NEVER expose internal error details to clients
- ALWAYS validate user input at API boundaries
