# Analytics Pipeline

A Python data pipeline for processing analytics events.

## Commands

- `make run` — Run the pipeline
- `make test` — Run tests
- `make lint` — Run linter

## Architecture

ETL pipeline with separate extract, transform, and load stages.

## Constraints

- NEVER process data without schema validation
- ALWAYS log pipeline stage transitions
