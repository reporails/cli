# Unreleased

### Added

- [CLI]: Inline Pro diagnostic counts per file card — free tier shows `⊕ N Pro diagnostics (K errors)` inside each file card instead of a separate Hints section
- [CLI]: Cross-file coordinate section — free tier shows which files interact (file ↔ file, type, count) without line-level detail
- [CLI]: Pro diagnostic counts in scorecard — `+ N Pro diagnostics (K errors · M warnings)` shows scale of findings available with upgrade
- [CLI]: Integrated CTA — `See all N findings with fixes → ails auth login` replaces the previous dim afterthought
- [META]: Add `reporails-cli` script alias in `pyproject.toml` — `uvx reporails-cli check` now works
- [META]: Add entry point verification gate in `scripts/pre-release-check.sh`

### Changed

- [CLI]: Replace Hints section with inline per-file Pro diagnostic counts and cross-file coordinates — interaction diagnostics shown in context, not disconnected
- [CORE]: Mapper daemon closes inherited FDs before daemonizing — prevents parent process (npx, CI) from hanging on pipe EOF
- [CORE]: Mapper daemon detects orphaned state (PPID=1) and shuts down within 30s — prevents indefinite persistence after ephemeral parent exits
- [CORE]: Fail-fast audit — add `logger.warning()` on 4 critical-path catches, narrow 12 bare `except Exception:` to specific types, justify 16 remaining with inline comments
- [CORE]: Scrub internal notation from code comments and docstrings (`api_client.py`, `merger.py`, `memory_checks.py`, `mapper.py`, `main.py`)
- [DOCS]: Rewrite READMEs for 0.5.x — current output format, correct flags, five categories
- [DOCS]: Update tier spec — cross-file from "Blocked" to "Coordinate" for free tier
- [DOCS]: Update UX spec — free tier mockup with inline Pro counts and cross-file coordinates

### Fixed

- [BUILD]: Add `scikit-learn` to runtime dependencies — required by mapper topic clustering (`AgglomerativeClustering`)
- [BUILD]: Fix `uvx reporails-cli` — add `reporails-cli` script alias so `uvx` resolves the executable
- [BUILD]: Fix post-publish smoke test — use `uvx --from reporails-cli ails` instead of `uvx reporails-cli`
- [CLI]: Log warning when mapper fails instead of silent degradation
- [TESTS]: Verify `client_check_count > 0` in smoke tests and `scripts/pre-release-check.sh`
- [DOCS]: Fix duplicate Install section in README, align npm description
