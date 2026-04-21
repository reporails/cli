# Unreleased

### Fixed
- [CLI]: Show progress output during mapper startup — fixes silent hang on projects with instruction files
- [CORE]: Add `warmup_done.wait()` in daemon `_dispatch` for `map_ruleset` — matches documented blocking behavior
- [CORE]: Add default `exclude_dirs` (`data`, `node_modules`, `.git`, `__pycache__`, `.venv`, etc.) to prevent walking massive non-instruction trees when no `.ails/config.yml` exists
