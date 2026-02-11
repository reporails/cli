# Unreleased

### Added
- [CLI]: Native `judge` MCP tool for verdict caching
- [CORE]: MCP e2e test suite (47 tests)

### Fixed
- [CORE]: Verdict parser mangled coordinate IDs with line numbers
- [CORE]: Validate guidance told LLM to shell out via Bash
- [CLI]: MCP server crashed on RuntimeError from init/validation
- [CORE]: ScanDelta IndexError on corrupted level in analytics cache
- [CORE]: Concurrent judgment cache writes lost data (now atomic)
- [CORE]: Recommended rules download failures silently swallowed

### Security
- [CORE]: Path traversal in judgment cache writes
