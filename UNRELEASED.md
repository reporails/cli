# Unreleased

### Added
- [CLI]: Phased progress spinner — shows "Loading rules..." / "Checking files..." / "Scoring..." during validation
- [ENGINE]: Add `metadata_keys` field to Check model — D checks write matched texts to pipeline annotations, M checks read them as injected args
- [ENGINE]: Add `count_at_most`, `count_at_least`, `check_import_targets_exist`, `filename_matches_pattern` mechanical probes
- [ENGINE]: Add signal catalog aliases: `glob_match`→`file_exists`, `max_line_count`→`line_count`, `glob_count`→`file_count`
- [CONFIG]: Add `--global` flag to `ails config set/get/list` — set defaults in `~/.reporails/config.yml` (supports `default_agent`, `recommended`)
- [AGENTS]: Add OpenAI Codex agent (`--agent codex`) with AGENTS.md instruction pattern
- [AGENTS]: Add generic agent config at rules level — targets AGENTS.md per agents.md convention
- [CONFIG]: Add `default_agent` option in `.reporails/config.yml` — sets agent when `--agent` not specified (CLI flag overrides)
- [CLI]: Add `ails config set/get/list` commands for managing `.reporails/config.yml` without manual editing
- [CLI]: Add agent hint — when running with generic agent and a specific agent is detected, suggest setting `default_agent`
- [META]: Add `.reporails/config.yml` with `default_agent`, `exclude_dirs`, and `disabled_rules`

- [ENGINE]: Dismissed violations filtered from `ails check` output (cached as pass verdicts, reset with `--refresh`)

### Changed
- [CLI]: Auto-detect agent from project files when `--agent` not specified — single unambiguous agent assumed, multiple agents default to generic
- [CLI]: Scorecard shows detected agent(s) above Scope line — `Agent: claude` for single, `Agents: claude, copilot` for multiple
- [CLI]: Scorecard category table redesigned — mini bars for per-category scores, centered columns, wider score bar, icon colors match severity
- [CLI]: Pending semantic checks shown inline with violations (was separate box below scorecard) — uses `?` icon, file headers show "N awaiting semantic"
- [CLI]: Experimental rules no longer displayed in output (was dim text below scorecard)
- [CLI]: Scorecard moved to bottom of output — violations shown first, score as conclusion
- [CLI]: Assessment box "Setup:" line replaced with "Scope:" — shows instruction files categorized by agent directory labels (rules, skills, etc.)
- [CLI]: `setup` command renamed to `install` — `setup` kept as hidden alias
- [CLI]: Install CTA shown for ephemeral (npx/uvx) users below scorecard
- [CLI]: Semantic CTA updated: `ails setup` → `ails install`
- [CLI]: `heal` command simplified to autoheal — silently applies all fixes, reports remaining violations and pending semantic rules (removed interactive prompts)
- [CLI]: `heal` adds `--format`/`-f` option (text/json) replacing `--non-interactive` flag
- [CLI]: Rename "(partial)" label to "(awaiting semantic)" across all output formats — clearer meaning for pending semantic evaluation
- [CLI]: JSON `evaluation` field changed from `"partial"` to `"awaiting_semantic"` (breaking: consumers checking this value need updating)
- [CLI]: `explain` unknown rule now shows rules grouped by namespace with counts instead of flat list
- [CLI]: `heal` prints "Run 'ails check' to see your updated score" after completion
- [CLI]: Wrap raw exceptions in user-friendly error messages (FileNotFoundError, RuntimeError, download failures)
- [CLI]: Exit code 2 for input errors in `explain` (unknown rule) and `--rules` (dir not found) — was exit 1
- [DOCS]: Add Configuration and Exit Codes sections to README
- [DOCS]: Consolidate duplicate command sections in npm README
- [CLI]: Scorecard layout — capability moved to own line below score, elapsed time shown in top-right
- [CLI]: Semantic color output — score, bar, capability level, violations, friction, and category table use green/yellow/red based on values (ASCII mode disables all colors)
- [ACTION]: Agent default changed from `claude` to empty (resolve via project config or generic fallback)
- [ACTION]: Add `-q` (quiet-semantic) flag — no human to judge semantic rules in CI
- [ACTION]: Add `exclude-dir` input for comma-separated directory exclusions
- [ACTION]: Fix agent conditional — pass `--agent` whenever non-empty (was comparing against `claude`)
- [DESCRIPTIONS]: Replace "CLAUDE.md" with "AI instruction files" in CLI, MCP, and setup strings
- [DOCS]: Restructure CLAUDE.md for ails check compliance (Boundaries, Testing, Commands sections)
- [DOCS]: Rephrase bare prohibitions in rule files to include actionable alternatives
- [META]: Add templates module to backbone.yml
- [CLI]: No `--agent` now defaults to "generic" (AGENTS.md only) instead of scanning all agents' files
- [CLI]: `--help` groups commands into panels (Commands, Configuration, Development) — `dismiss` and `judge` hidden as plumbing
- [RULES]: No `--agent` flag loads core rules only; agent-specific rules require explicit `--agent`

### Testing
- [SMOKE]: Add mutation-tested E2E smoke layer (`tests/smoke/`, 46 tests) — covers agent scoping, cross-agent contamination, template context, hint messages, violation location accuracy, nested file discovery, empty agent edge case, config-only detection, deduplication, generic agent template, input validation, default_agent config
- [SMOKE]: Add E2E tests for all CLI commands (60 tests) — version, explain, heal, map, dismiss, judge, install, update --check, config set/get/list with --global, check flags (--strict, --verbose, --ascii, --exclude-dir, -f json)
- [UNIT]: Add test coverage for `action/summary.py` (score table, status, categories, violations, CLI entry point)
- [CI]: Add `test-action.yml` workflow — regression tests for GitHub Action (pass/fail scenarios, output verification)
- [UNIT]: Add tests for mechanical check gaps — blocking behavior across rules, M→D→S interleaved sequence, content_absent multi-file, negate on file_exists/directory_exists (17 tests)
- [SMOKE]: Add E2E tests for mechanical checks through `ails check` — violations, locations, metadata, text output, oversized files (6 tests)
- [UNIT]: Refactor test suite — parametrize duplicated cases, add boundary/edge-case tests, relocate pure unit tests from integration/
- [INTEGRATION]: Add pipeline output stability tests — run full validation against committed fixtures, assert deterministic fields with regeneration flag

### Fixed
- [ENGINE]: Deduplicate semantic JudgmentRequests by file path — multiple D matches in the same file produce one LLM evaluation, not N
- [CONFIG]: Malformed YAML config files now log warnings instead of failing silently — applies to project, global, and agent configs
- [CONFIG]: Malformed project config now applies global defaults (was returning hardcoded defaults)
- [CLI]: Empty-files hint now shows the correct instruction file per agent (was hardcoded to CLAUDE.md)
- [CLI]: Unknown `--agent` values now error with exit code 2 and list known agents (was silently ignored)
- [CLI]: `--agent` values are now case-insensitive (`Claude` → `claude`)
- [CLI]: Invalid `--format` values now error with exit code 2 and list valid formats (was silently accepted)
- [CLI]: Extract `_validate_agent()` and `_validate_format()` helpers — shared between `check` and `heal`
- [ENGINE]: `--agent generic` now falls back to file-derived template context (was returning empty vars)
- [ENGINE]: JSON output uses deduplicated violations (was serializing raw duplicates)
- [ENGINE]: Without `--agent`, was scanning all agent files with identical rules — now defaults to generic (AGENTS.md only)
- [HEAL]: Default `--agent` changed from `claude` to empty (matching `check` command)
- [RULES]: Without `--agent`, no longer loads all agent rules indiscriminately — core rules only
- [TESTS]: Integration hint tests now force `-f text` (were failing in CI where `CI=true` defaults to JSON)
- [TESTS]: Heal tests use targeted `_is_interactive` mock instead of full `sys` mock (was causing TypeError in CI)
- [ACTION]: Strict test fixture uses wall-of-prose CLAUDE.md that triggers core rule violations
- [ENGINE]: Rule compiler crashes on `paths: include: null` in YAML rules — `dict.get()` returns `None` not default when key exists with null value (was `TypeError: 'NoneType' object is not iterable`)
- [ENGINE]: `exclude_dirs` config not applied during agent file discovery — test fixtures were scanned as real instruction files
- [ENGINE]: `--refresh` flag did not clear agent or rule caches — only affected semantic judgment cache

