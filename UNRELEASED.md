# Unreleased

### Added
- [FORMATTERS]: Per-surface health scores in `ails check` summary scorecard

### Fixed
- [CORE]: Charge classifier misses for `append`, `stage`, `compose` and 5 other verbs
- [CORE]: Ambiguous verbs at position 0 incorrectly classified as neutral
- [CORE]: Non-ambiguous verbs demoted to `nsubj` by spaCy misparse not rescued
