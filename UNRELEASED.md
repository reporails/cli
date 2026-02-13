# Unreleased

### Added
- [CORE]: Pure Python regex engine replacing OpenGrep binary
- [CORE]: Adversarial test suite for regex engine (76 tests)

### Changed
- [META]: Version bump to 0.3.0
- [DOCS]: Updated all specs to reflect regex engine migration

### Removed
- [CORE]: OpenGrep binary dependency and download pipeline
- [CORE]: Semgrepignore support
- [CLI]: OpenGrep version display from `ails version`

### Fixed
- [CORE]: Compiler crash on binary YAML files (UnicodeDecodeError)
- [CORE]: Mechanical checks crash on string args from YAML (type coercion via `_safe_float`)
- [CORE]: Invalid severity in agent config no longer crashes registry (logs warning, keeps original)
- [CORE]: `is_initialized()` now checks for `core/` subdirectory, not just rules path existence
- [CORE]: Negated deterministic handler reuses `resolve_location()` instead of inline template logic
- [CLI]: Exit code 2 for input errors (bad path, missing args), exit 1 for violations
- [CLI]: Improved help text for target and agent arguments
- [CLI]: First-run feedback: logs "Downloading rules framework..." before auto-init
- [CLI]: User-friendly error wrapping for download failures (httpx)
- [CLI]: Word-boundary truncation for level labels, violation messages, and semantic rule titles
- [CLI]: JSON output returns valid structure when no instruction files found
- [MCP]: Narrowed exception handling from broad `Exception` to specific types
- [MCP]: Added `is_dir()` validation to all tool handlers
- [MCP]: Improved tool descriptions with output format info and examples
- [MCP]: Judge tool returns detailed `{recorded, failed}` feedback instead of silent `{recorded: 0}`
- [PERF]: Path-based pre-grouping avoids O(files x checks) inner loop for path-filtered checks
- [PERF]: Combined regex patterns batch simple checks into alternation with named groups (~10-50x speedup)
- [PERF]: Capability detection uses first-match-only early exit
- [TEST]: Added unit tests for semantic request building (12 tests)
- [TEST]: Added unit tests for applicability detection and rule filtering (14 tests)
- [TEST]: Added unit tests for engine helper cache filtering (6 tests)
- [TEST]: Added type safety tests for mechanical checks with string/invalid args
