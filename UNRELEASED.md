# Unreleased

### Added
- Agents: Add OpenAI Codex agent (`--agent codex`) with AGENTS.md instruction pattern
- Agents: Add generic agent config at rules level — targets AGENTS.md per agents.md convention
- Config: Add `default_agent` option in `.reporails/config.yml` — sets agent when `--agent` not specified (CLI flag overrides)

### Added
- [META]: Add `.reporails/config.yml` with `default_agent`, `exclude_dirs`, and `disabled_rules`

### Changed
- [DOCS]: Restructure CLAUDE.md for ails check compliance (Boundaries, Testing, Commands sections)
- [DOCS]: Rephrase bare prohibitions in rule files to include actionable alternatives
- [META]: Add templates module to backbone.yml
- CLI: No `--agent` now defaults to "generic" (AGENTS.md only) instead of scanning all agents' files
- Rules: No `--agent` flag loads core rules only; agent-specific rules require explicit `--agent`

### Testing
- Smoke: Add mutation-tested E2E smoke layer (`tests/smoke/`, 46 tests) — covers agent scoping, cross-agent contamination, template context, hint messages, violation location accuracy, nested file discovery, empty agent edge case, config-only detection, deduplication, generic agent template, input validation, default_agent config

### Fixed
- CLI: Empty-files hint now shows the correct instruction file per agent (was hardcoded to CLAUDE.md)
- CLI: Unknown `--agent` values now error with exit code 2 and list known agents (was silently ignored)
- CLI: `--agent` values are now case-insensitive (`Claude` → `claude`)
- CLI: Invalid `--format` values now error with exit code 2 and list valid formats (was silently accepted)
- CLI: Extract `_validate_agent()` and `_validate_format()` helpers — shared between `check` and `heal`
- Engine: `--agent generic` now falls back to file-derived template context (was returning empty vars)
- Engine: JSON output uses deduplicated violations (was serializing raw duplicates)
- Engine: Without `--agent`, was scanning all agent files with identical rules — now defaults to generic (AGENTS.md only)
- Heal: Default `--agent` changed from `claude` to empty (matching `check` command)
- Rules: Without `--agent`, no longer loads all agent rules indiscriminately — core rules only
