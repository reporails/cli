# Delta CLI

A command-line tool for operators to inspect and replay failed jobs.

## Commands

- `cargo build --release` — Build the release binary
- `cargo test` — Run the test suite
- `delta replay <job-id>` — Replay one failed job

## Architecture

Subcommands share a single client that wraps the internal job API.

## Constraints

- NEVER replay a job without confirming its idempotency key
- ALWAYS print a summary before exiting
- MUST exit non-zero when a replay fails
- Keep subcommand output stable for scripting
