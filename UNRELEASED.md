# Unreleased

### Added
- Agents: Add OpenAI Codex agent (`--agent codex`) with AGENTS.md instruction pattern
- Agents: Add generic agent config at rules level — targets AGENTS.md per agents.md convention
- Config: Add `default_agent` option in `.reporails/config.yml` — sets agent when `--agent` not specified (CLI flag overrides)
- CLI: Add `ails config set/get/list` commands for managing `.reporails/config.yml` without manual editing
- CLI: Add agent hint — when running with generic agent and a specific agent is detected, suggest setting `default_agent`
- [META]: Add `.reporails/config.yml` with `default_agent`, `exclude_dirs`, and `disabled_rules`

- CLI: Interactive heal for all violation types — three-phase flow (auto-fix, manual violations, semantic judgments) with dismiss/skip for deterministic violations
- Engine: Dismissed violations filtered from `ails check` output (cached as pass verdicts, reset with `--refresh`)

### Changed
- CLI: Rename "(partial)" label to "(awaiting semantic)" across all output formats — clearer meaning for pending semantic evaluation
- CLI: JSON `evaluation` field changed from `"partial"` to `"awaiting_semantic"` (breaking: consumers checking this value need updating)
- CLI: `explain` unknown rule now shows rules grouped by namespace with counts instead of flat list
- CLI: `heal` verdict prompt shows legend on first prompt explaining [p]ass/[f]ail/[s]kip/[d]ismiss
- CLI: `heal` prints "Run 'ails check' to see your updated score" after completion
- CLI: Wrap raw exceptions in user-friendly error messages (FileNotFoundError, RuntimeError, download failures)
- CLI: Exit code 2 for input errors in `explain` (unknown rule) and `--rules` (dir not found) — was exit 1
- [DOCS]: Add Configuration and Exit Codes sections to README
- [DOCS]: Consolidate duplicate command sections in npm README
- CLI: Scorecard layout — capability moved to own line below score, elapsed time shown in top-right
- CLI: Semantic color output — score, bar, capability level, violations, friction, and category table use green/yellow/red based on values (ASCII mode disables all colors)
- Action: Agent default changed from `claude` to empty (resolve via project config or generic fallback)
- Action: Add `-q` (quiet-semantic) flag — no human to judge semantic rules in CI
- Action: Add `exclude-dir` input for comma-separated directory exclusions
- Action: Fix agent conditional — pass `--agent` whenever non-empty (was comparing against `claude`)
- Descriptions: Replace "CLAUDE.md" with "AI instruction files" in CLI, MCP, and setup strings
- [DOCS]: Restructure CLAUDE.md for ails check compliance (Boundaries, Testing, Commands sections)
- [DOCS]: Rephrase bare prohibitions in rule files to include actionable alternatives
- [META]: Add templates module to backbone.yml
- CLI: No `--agent` now defaults to "generic" (AGENTS.md only) instead of scanning all agents' files
- Rules: No `--agent` flag loads core rules only; agent-specific rules require explicit `--agent`

### Testing
- Smoke: Add mutation-tested E2E smoke layer (`tests/smoke/`, 46 tests) — covers agent scoping, cross-agent contamination, template context, hint messages, violation location accuracy, nested file discovery, empty agent edge case, config-only detection, deduplication, generic agent template, input validation, default_agent config
- Unit: Add test coverage for `action/summary.py` (score table, status, categories, violations, CLI entry point)
- CI: Add `test-action.yml` workflow — regression tests for GitHub Action (pass/fail scenarios, output verification)

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
- Tests: Integration hint tests now force `-f text` (were failing in CI where `CI=true` defaults to JSON)
- Tests: Heal tests use targeted `_is_interactive` mock instead of full `sys` mock (was causing TypeError in CI)
- Action: Strict test fixture uses wall-of-prose CLAUDE.md that triggers core rule violations
- Engine: Rule compiler crashes on `paths: include: null` in YAML rules — `dict.get()` returns `None` not default when key exists with null value (was `TypeError: 'NoneType' object is not iterable`)
- Engine: `exclude_dirs` config not applied during agent file discovery — test fixtures were scanned as real instruction files
- Engine: `--refresh` flag did not clear agent or rule caches — only affected semantic judgment cache


