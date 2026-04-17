# Unreleased

### Fixed

- [BUILD]: Add `scikit-learn` to runtime dependencies — required by mapper topic clustering (`AgglomerativeClustering`)
- [CLI]: Log warning when mapper fails instead of silent degradation
- [TESTS]: Verify `client_check_count > 0` in smoke tests and `scripts/pre-release-check.sh`
- [DOCS]: Fix duplicate Install section in README, align npm description

### Changed

- [CORE]: Fail-fast audit — add `logger.warning()` on 4 critical-path catches, narrow 12 bare `except Exception:` to specific types, justify 16 remaining with inline comments
- [CORE]: Scrub internal notation from code comments and docstrings (`api_client.py`, `merger.py`, `memory_checks.py`, `mapper.py`, `main.py`)
- [DOCS]: Rewrite READMEs for 0.5.x — current output format, correct flags, five categories
