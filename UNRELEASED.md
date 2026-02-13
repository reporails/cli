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
