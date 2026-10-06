# Demo project

## Commands

Use `uv` for every Python command in this repository.

Install dependencies with `uv sync` after every pull.
Run `uv run pytest` before every commit.
Commit the updated lockfile together with your change.

## Boundaries

*Do not edit files under `gen/` by hand.*
Run `make gen` to regenerate files under `gen/`.
