# Beta Frontend

A React dashboard for operations staff to review flagged transactions.

## Commands

- `npm install` — Install dependencies
- `npm run dev` — Start the local dev server
- `npm run build` — Produce a production bundle

## Architecture

Feature modules are colocated with their tests under `src/features/`.
Shared UI primitives live under `src/components/ui/`.

## Constraints

- NEVER commit an API key or secret to the repository
- ALWAYS run the linter before opening a pull request
- MUST keep component files under 300 lines
- Prefer composition over deep prop drilling
