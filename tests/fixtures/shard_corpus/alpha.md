# Alpha Service

A payments microservice handling refunds and settlement batches.

## Commands

- `make build` — Compile the service binary
- `make test` — Run the unit test suite
- `make migrate` — Apply pending database migrations

## Architecture

The service separates ingestion, ledger, and settlement into distinct modules
that communicate over an internal queue.

## Constraints

- NEVER log full card numbers or CVV codes
- ALWAYS validate settlement totals against the ledger before closing a batch
- MUST retry failed webhook deliveries with exponential backoff
- Avoid holding the ledger lock across a network call
