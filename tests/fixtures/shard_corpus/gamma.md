# Gamma Worker

A background worker that drains the event queue and writes to the warehouse.

## Commands

- `poetry install` — Install dependencies
- `poetry run worker` — Start the worker process
- `poetry run pytest` — Run the test suite

## Architecture

Events are consumed in batches, transformed, and written to the warehouse in a
single transaction per batch.

## Constraints

- NEVER acknowledge a batch before the write transaction commits
- ALWAYS emit a metric on batch completion
- MUST cap batch size at the configured maximum
- Do not swallow deserialization errors silently
