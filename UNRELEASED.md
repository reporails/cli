# Unreleased

### Added
- [CLI]: Native `judge` MCP tool for verdict caching
- [CORE]: MCP e2e test suite (53 tests)
- [CLI]: Circuit breaker for validate-fix-validate loops
- [CORE]: Pipeline state engine with per-rule ordered check execution
- [CORE]: SARIF gather-distribute pattern for batched OpenGrep + per-rule consumption
- [CORE]: In-memory check result cache for cross-rule mechanical dedup
- [CORE]: D→M annotation propagation (mechanical checks attach metadata to targets)

### Changed
- [CORE]: Split 7 oversized modules (models, cache, registry, init, engine, checks, cli/main)
- [META]: Stricter tooling — ruff ARG/C90/PERF/RUF rules, pylint structural enforcement (300-line modules, 12 branches)

### Fixed
- [CORE]: explain_tool returned empty rules (missing paths + tier filtering)
- [CORE]: Template vars unresolved when engine uses custom rules_paths
- [CORE]: Verdict parser mangled coordinate IDs with line numbers
- [CORE]: Validate guidance told LLM to shell out via Bash
- [CLI]: MCP server crashed on RuntimeError from init/validation
- [CORE]: ScanDelta IndexError on corrupted level in analytics cache
- [CORE]: Concurrent judgment cache writes lost data (now atomic)
- [CORE]: Recommended rules download failures silently swallowed

### Security
- [CORE]: Path traversal in judgment cache writes
