# Unreleased

### Added
- [CLI]: `ails heal` auto-fix phase — silently applies safe fixes before semantic prompts
- [CLI]: `ails heal` command for interactive semantic rule evaluation (pass/fail/skip/dismiss)
- [CORE]: Auto-fixer registry with 5 additive fixers (constraints, commands, testing, sections, structure)
- [MCP]: `heal` tool — applies auto-fixes and returns remaining semantic judgment requests
- [CORE]: Structural hash for smarter cache invalidation — cosmetic edits no longer clear semantic verdicts
- [CORE]: Pure Python regex engine replacing OpenGrep binary
- [CORE]: Adversarial test suite for regex engine (76 tests)
- [HOOKS]: PostToolUse auto-validation hook for instruction file edits

### Changed
- [REPO]: Gitignore development internals (docs/specs, CLAUDE.md, .claude/rules, hooks, skills, settings)
- [CORE]: Scan targets now include config files for path-filtered rules (`get_all_scannable_files`)
- [JSON]: `pending_semantic` and `skipped_experimental` omitted from JSON output when absent (avoids null-chaining)
- [META]: Version bump to 0.3.0
- [DOCS]: Updated all specs to reflect regex engine migration
- [MCP]: Validate tool returns structured JSON instead of formatted text
- [MCP]: Semantic judgment requests now carry full file content (up to 8KB) instead of 5-line snippets
- [MCP]: Replaced `_instructions` text blob with structured `_semantic_workflow` object for agent consumption
- [MCP]: Rewrote all tool descriptions with output format info and usage guidance
- [MCP]: Content-aware circuit breaker tracks file mtimes instead of blunt call counter (allows edit-validate cycles)
- [MCP]: Error responses now return structured JSON with `error` and `message` keys

### Removed
- [CORE]: OpenGrep binary dependency and download pipeline
- [CORE]: Semgrepignore support
- [CLI]: OpenGrep version display from `ails version`

### Fixed
- [CORE]: Content rule violations now attributed to root instruction file (`CLAUDE.md`) instead of skill files or scoped snippets
- [CORE]: Per-file size violations (`line_count`, `byte_size`) now attributed to the violating file, not the rule-level target
- [CORE]: Cache hash crash on non-UTF8 instruction files (`UnicodeDecodeError` now caught)
- [CORE]: Feature merge in capability detection used overwrite instead of OR — filesystem-detected features could be lost
- [CORE]: Regex compiler crash on malformed rule YAML with non-list `rules` field
- [CORE]: Removed duplicate `dedupe_violations` from scorer (canonical copy lives in sarif module)
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
- [TEST]: Updated MCP e2e tests for JSON output, content-aware circuit breaker, and semantic workflow
- [TEST]: MCP e2e test includes `heal` tool in expected tool set
