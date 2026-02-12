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
