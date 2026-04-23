# Unreleased

### Added
- [FORMATTERS]: Per-surface health scores with file counts in `ails check` summary scorecard
- [CORE]: Check-level `replaces`, `severity`, `message` override fields on `Check` model
- [CORE]: `Severity.LOW` (weight 1.5) and `Severity.INFO` (weight 1.0) severity levels
- [CORE]: Rule inheritance via `supersedes` — agent rules inherit and optionally replace CORE checks
- [CORE]: `frontmatter_extra_keys` mechanical check — warns when frontmatter has keys the agent ignores
- [RULES]: CLAUDE:S:0012 path-scope-declared — detects `globs:` misuse and extra frontmatter keys
- [RULES]: CURSOR:S:0001 path-scope-declared with `supersedes: CORE:S:0038`
- [RULES]: COPILOT:S:0001 `supersedes: CORE:S:0038`

### Fixed
- [CORE]: Charge classifier misses for `append`, `stage`, `compose` and 5 other verbs
- [CORE]: Ambiguous verbs at position 0 incorrectly classified as neutral
- [CORE]: Non-ambiguous verbs demoted to `nsubj` by spaCy misparse not rescued
- [CORE]: Quote-scope-aware sentence splitting — don't split inside quoted or parenthetical spans
- [CORE]: Backtick filter false positives on position-0 verbs appearing in later backtick spans
- [CORE]: M-probe pipeline skipped deterministic checks in mixed-type (mechanical+deterministic) rules
- [CORE]: Deterministic check file targeting now uses `match_files()` for full property-based matching
- [FORMATTERS]: Surface file counts from mapper discovery, not just files with findings
- [FORMATTERS]: IP-clean display labels for topic overload and isolated instructions
- [RULES]: CORE:S:0038 made agent-agnostic with plain test fixtures
