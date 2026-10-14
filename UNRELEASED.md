# Unreleased

### Added

### Changed

### Fixed

### Removed

- The `reporails_cli` package no longer exports `__version__` (`ails version` and `importlib.metadata.version("reporails-cli")` report it), `ValidationResult`, `JudgmentRequest` or `JudgmentResponse`, and `formatters.json.format_result` / `format_score` and `formatters.github.format_result` / `format_annotations` are gone; no command produced or called them.

### Internal

- The source passes pylint with no findings, and the pylint gate now fails on any new one.
- Code that no command reached is removed.
- Tests: two exclusion tests compare paths the same way on Windows.
- Tests: the marker check counts a module-level marker list, as pytest does, so each test carries exactly one lane.
