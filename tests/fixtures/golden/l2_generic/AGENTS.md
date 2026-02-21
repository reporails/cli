# Data Pipeline

A Python ETL pipeline for processing event streams.

## Commands

- `make run` — Run the pipeline
- `make test` — Run tests
- `make lint` — Check code style

## Architecture

ETL pipeline with separate extract, transform, and load stages.

## Constraints

- MUST validate schemas before processing
- NEVER process data without logging
- MUST handle partial failures gracefully
