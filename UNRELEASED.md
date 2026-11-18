# Unreleased

### Added

### Changed

### Fixed

- The x-ray page shows every instruction file a kept message loaded as restored after a compaction, not only the last one.
- The x-ray page no longer re-walks the project and `~/.claude` on every refresh; it lists the files again when a config or settings file or an instruction folder changes.
- A refused `--format github` run now escapes `%` and carriage returns in the error annotation.
- The configuration reference now documents what a refused or unreachable `--format json` run prints and that it exits 1 before any check runs.

- A model that cannot be fetched or repaired offline now names the real cause (`--offline` or `AILS_OFFLINE`, or `AILS_MODEL_OFFLINE`) instead of always blaming `AILS_MODEL_OFFLINE`.

- `ails check --offline` no longer leaves offline mode on after the run, and a background mapper started by that run no longer refuses model repairs for later online runs.

- MCP `validate` no longer asks the service before every call: a passed check is reused for 60 seconds, and the unreachable reply tells you to set `AILS_OFFLINE=1` in the MCP server's environment instead of naming a CLI flag.

- After a rate-limit reply, repeated `ails check` runs (hooks, watchers) no longer ask the service each time: they show the local "Try again in ~N min" until the limit resets.

- A refused `--format github` run escapes `%` and carriage returns in the error annotation.

### Removed

### Internal
- Docstring and test-fixture examples use neutral text.
- Heal reads a file through the one file reader.
- The deterministic checks use the run's exclusions.
