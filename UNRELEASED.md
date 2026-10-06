# Unreleased

### Added

### Changed

### Fixed

- `ails rules` and `ails explain` no longer describe the one-instruction-per-sentence and broad-conditional-scope rules as needing a server connection; both run on your machine.
- Python 3.13: a symlink loop in a project is skipped instead of being treated as a normal file.
- Check: the summary names the agent you passed with --agent, also when the server cannot be reached.
- GitHub Action: the min-score gate fails when content checks were skipped, instead of passing on a partial score.
- MCP: a validate call that hit a busy or slow server can be retried on the same file instead of being refused as a repeat, and the reply says it is retryable and how long to wait.

### Removed

### Internal

- Dropped the unused all-caps token field from the uploaded instruction map and removed the unused rule-tier derivation helpers.
- CI and the release gate run the QA suite on Python 3.12 and 3.13; `typer` is capped below 0.22; CLI tests no longer use `CliRunner.isolated_filesystem`.
