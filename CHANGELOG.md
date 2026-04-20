# Changelog

## 0.5.3

### Added

- `ails update` command — upgrades CLI to latest version via `uv tool upgrade`
- `ails install` now installs `ails` to PATH (via `uv tool install`) in addition to MCP config
- MCP config uses direct binary path when available (faster startup, works offline)

### Changed

- Global mapper daemon — single process at `~/.reporails/daemon/` serves all projects (~1GB RAM saved per additional project)
- Map cache moved to `~/.reporails/cache/map-cache.json` with LRU eviction (cap 5000)
- Per-project caches moved to `~/.reporails/cache/projects/<hash>/`
- `ails daemon start/stop/status` no longer require a path argument (daemon is global, path arg deprecated)
- Project `.ails/` directory is now config-only — no runtime artifacts written there

### Fixed

- Eliminate charge inversions in classifier — compound instructions ("Use X. Do not Y") now marked AMBIGUOUS instead of wrongly charged (0.30% → 0.03% inversion rate)
- Colon-label rescue for "Label: Use X" / "Label: Never Y" patterns previously neutralized as headings
- Add "pass" to ambiguous verb set — prevents status labels from triggering imperative classification
- Late-constraint guard catches negation after sentence/clause boundaries in imperative-classified atoms

## 0.5.2

### Added

- Inline Pro diagnostic counts per file card — free tier shows `⊕ N Pro diagnostics (K errors)` inside each file card instead of a separate Hints section
- Cross-file coordinate section — free tier shows which files interact (file ↔ file, type, count) without line-level detail
- Pro diagnostic counts in scorecard — `+ N Pro diagnostics (K errors · M warnings)` shows scale of findings available with upgrade
- Integrated CTA — `See all N findings with fixes → ails auth login` replaces the previous dim afterthought
- `reporails-cli` script alias in `pyproject.toml` — `uvx reporails-cli check` now works
- Entry point verification gate in `scripts/pre-release-check.sh`

### Changed

- Extract display logic from `interfaces/cli/main.py` into `formatters/text/display.py`, `display_constants.py`, and `scorecard.py` — eliminates 12 pylint structural violations, reduces `main.py` from 1118 to 315 lines
- Replace Hints section with inline per-file Pro diagnostic counts and cross-file coordinates — interaction diagnostics shown in context, not disconnected
- Mapper daemon closes inherited FDs before daemonizing — prevents parent process (npx, CI) from hanging on pipe EOF
- Mapper daemon detects orphaned state (PPID=1) and shuts down within 30s — prevents indefinite persistence after ephemeral parent exits
- Fail-fast audit — add `logger.warning()` on 4 critical-path catches, narrow 12 bare `except Exception:` to specific types, justify 16 remaining with inline comments
- Scrub internal notation from code comments and docstrings
- Rewrite READMEs for 0.5.x — current output format, correct flags, five categories
- Update tier spec — cross-file from "Blocked" to "Coordinate" for free tier

### Fixed

- Pre-compile `KNOWN_CODE_TOKENS` regex as single alternation pattern at module level — eliminates ~26,500 `re.compile()` calls per typical run
- Fix `ails map` crash when agent config files exist outside project directory (`~/.claude/settings.json`)
- Add `scikit-learn` to runtime dependencies — required by mapper topic clustering
- Fix `uvx reporails-cli` — add `reporails-cli` script alias so `uvx` resolves the executable
- Fix post-publish smoke test — use `uvx --from reporails-cli ails` instead of `uvx reporails-cli`
- Log warning when mapper fails instead of silent degradation
- Fix duplicate Install section in README, align npm description

## 0.5.1

Patch release — 0.5.0 published with a direct URL dependency (`en-core-web-sm`) that PyPI accepted but pip/uvx cannot resolve. The spaCy language model is now auto-downloaded on first run instead of declared as a dependency.

## 0.5.0

### Self-contained install

Rules, schemas, and agent configs are now bundled inside the Python wheel. `ails check` works immediately after `pip install reporails-cli` — no `ails install` step, no external rules download. The 222 bundled rule files ship as package data via hatch `force-include`. The separate `rules/` repo is no longer a runtime dependency.

### New pipeline architecture

The check pipeline was rebuilt from scratch: discover files → run mechanical probes → map instruction content → run client checks → merge results. Findings from all sources converge into a single `CombinedResult` with normalized file paths, deduplication, and per-file grouping. The old `engine.py` / `pipeline.py` / `scorer.py` stack is removed.

### ONNX embeddings (no torch)

`sentence-transformers` and PyTorch are replaced by a bundled ONNX export of `all-MiniLM-L6-v2` loaded via `onnxruntime` + `tokenizers`. The embedding output is bit-identical to the PyTorch baseline. A `sys.meta_path` import hook blocks `torch` from loading through spaCy's thinc backend, eliminating a 20-second cold-start penalty. The installed venv footprint drops by several hundred MB.

### Mapper daemon

A persistent background process (`ails daemon start`) keeps the embedding model loaded between runs. The daemon binds its Unix socket before model warmup and warms in a background thread, so cache-hit requests return instantly. Per-file embedding results are cached by content hash. Idle timeout is 1 hour (configurable via `AILS_DAEMON_IDLE_S`).

### Content-quality checks

25 rules migrated from regex pattern matching to atom-based content queries. The mapper classifies each instruction into atoms with charge (directive/constraint/neutral/ambiguous), modality, and specificity. Content queries like `has_non_italic_constraints`, `has_mermaid_blocks`, and `has_charged_headings` run against the atom map. A new `heading-as-instruction` rule flags headings that carry charge instead of organizing content.

### Heal command

`ails heal [PATH]` auto-fixes instruction file issues. Four mechanical fixers operate at the atom level: backtick wrapping for code constructs, bold→italic on constraints, full-sentence italic, and charge ordering. Reports remaining violations after fixes. Available as both CLI command and MCP tool.

### File type classification

Agent configs define file types with properties (format, cardinality, loading, scope, precedence). Rules declare which file types they target via `match: {type: ...}`. Rules that target a file type not present in the project are silently skipped — no false positives from missing surfaces. Project level is emergent from file type property coverage instead of a stored `level:` field.

### Inline import expansion

The mapper expands `@path` inline imports before tokenization. Claude Code and Gemini CLI splice imported file content at the reference position — the mapper sees the same expanded content. Resolves relative to importing file, expands `~/`, recurses up to 5 hops, detects circular imports.

### External file discovery

Agent configs can reference external paths (`~/...`, `/absolute/...`). Auto-memory files (`~/.claude/projects/*/memory/MEMORY.md`), user-level rules, and managed policies are now part of the instruction surface. Memory index validation catches broken links and missing frontmatter.

### Redesigned output

Text output redesigned — "Reporails — Diagnostics" header with file type breakdown and instruction counts (directive/constraint/ambiguous). Files grouped by type in bordered cards, sorted worst-first. Scorecard at the bottom with score bar, agent, scope, and results. JSON output grouped by file with `fix` field. GitHub formatter emits annotations with JSON summary on the last line.

### Stopwords tooling

`ails stopwords extract` parses alternation patterns from `checks.yml` into `vocab.yml` term lists. `ails stopwords sync` compiles terms back into patterns (with `--dry-run`). Staleness detection flags drift between vocab.yml and checks.yml.

### Breaking changes

- Level labels renamed: Organized→Structured, Distributed→Substantive, Contextual→Actionable, Extensible→Refined, Governed→Adaptive
- `Rule.targets` string replaced by `Rule.match` (FileMatch dataclass) with `type`, `format`, and property filters
- `rule.yml` renamed to `checks.yml` with `checks:` top-level key
- Severity moved from Check to Rule level
- Removed commands: `update`, `sync`, `topo`, `lint`, `dismiss`, `judge`
- Removed flags: `--experimental`, `--no-update-check`, `-q`
- Removed output formats: `compact`, `brief`
- `--strict` now exits 1 on any finding (was errors only)
- Project config directory renamed from `.reporails/` to `.ails/`
- JSON output schema changed: `files`/`stats` replaces `score`/`level`/`violations`

### Bug fixes

- Deterministic checks grouped by `rule.match.type` — rules with `match: {type: scoped_rule}` no longer fire on main files, eliminating ~215 false positives
- File path normalization unifies paths from all three sources (mechanical, client, server) to project-relative, fixing 60+ → 31 file key fragmentation in JSON output
- `expect: present` regex semantics inverted — was reporting matches as violations
- Duplicate findings from mechanical checks processed as regex eliminated (390 empty-message findings)
- Rich `MarkupError` crash on severity values and bracket characters in rule IDs
- Daemon JSON round-trip preserving all Atom fields
- `file_absent` false positives when match_type is set but no files of that type are classified
- Regex timeout (500ms) guards against catastrophic backtracking
- Graceful fallback when ONNX model is not bundled (CI/from-source installs)
- Score returns 0.0 instead of 10.0 when no rules checked (L0)

### GitHub Action

Action updated for the new pipeline. `parse_result.py` computes score, level, and violation count from the `CombinedResult` JSON. Invalid flags (`--no-update-check`, `-q`) removed. `--exclude-dir` corrected to `--exclude-dirs`.

### Dependencies

- Rules bundled (no external framework dependency)
- `onnxruntime>=1.18,<2`, `tokenizers>=0.19,<1` (replaces sentence-transformers + torch)
- `spacy>=3.8.11,<4` with `en_core_web_sm-3.8.0`
- `numpy>=1.26,<3`

## 0.4.0

### Multi-agent support

Agent detection and scoping overhauled. `ails check` auto-detects agents from project files — single unambiguous agent is assumed, multiple agents default to generic. Without `--agent`, only core rules load; agent-specific rules require an explicit flag. Added OpenAI Codex agent (`--agent codex`) with AGENTS.md instruction pattern, plus a generic agent config targeting AGENTS.md. Glob patterns supported in agent excludes (e.g., `CLAUDE:*`). Agent config schema v0.2.0 fields (`prefix`, `name`, `core`) now loaded.

### Configuration system

New `ails config set/get/list` commands for managing `.reporails/config.yml` without manual editing. `--global` flag writes to `~/.reporails/config.yml`. Added `default_agent` option — sets agent when `--agent` not specified (CLI flag overrides). Agent hint suggests setting `default_agent` when running generic with a specific agent detected.

### New mechanical checks

Added `file_absent` check (verifies a file does NOT exist), `count_at_most`, `count_at_least`, `check_import_targets_exist`, and `filename_matches_pattern` probes. `metadata_keys` field on the Check model enables D→M annotation propagation — D checks write matched texts to pipeline annotations, M checks read them as injected args. Check aliases registered: `file_tracked`→`git_tracked`, `memory_dir_exists`→`directory_exists`, `total_size_check`→`aggregate_byte_size`. Signal catalog aliases: `glob_match`→`file_exists`, `max_line_count`→`line_count`, `glob_count`→`file_count`.

### Test harness

Added fail scaffold system — auto-generates fail fixtures for structural M checks (`filename_matches_pattern`, `glob_count`, `file_count`, `file_absent`). Pass scaffold extended with `file_absent` support (removes forbidden file from fixture). Multi-agent prefix dispatch, effectiveness scoring, and coverage baseline added to harness.

### Scorecard redesign

Scorecard moved to bottom of output — violations shown first, score as conclusion. Category table redesigned with mini bars, centered columns, and severity-colored icons. Capability moved to own line below score, elapsed time shown in top-right. Semantic color output throughout — score, bar, capability level, violations, friction, and category table use green/yellow/red (ASCII mode disables colors). Pending semantic checks shown inline with violations using `?` icon. "Setup:" replaced with "Scope:" showing instruction files by agent directory labels.

### `ails heal` simplified

Heal command simplified to autoheal — silently applies all fixes, reports remaining violations and pending semantic rules (interactive prompts removed). Added `--format`/`-f` option (text/json) replacing `--non-interactive` flag. Dismissed violations filtered from output (cached as pass verdicts, reset with `--refresh`).

### CLI polish

- `setup` command renamed to `install` — `setup` kept as hidden alias
- `--help` groups commands into panels (Commands, Configuration, Development) — `dismiss` and `judge` hidden as plumbing
- Phased progress spinner shows "Loading rules..." / "Checking files..." / "Scoring..." during validation
- `explain` unknown rule shows rules grouped by namespace with counts instead of flat list
- Install CTA shown for ephemeral (npx/uvx) users below scorecard
- Raw exceptions wrapped in user-friendly error messages (FileNotFoundError, RuntimeError, download failures)
- Exit code 2 for input errors in `explain` and `--rules` — was exit 1
- `"partial"` evaluation label renamed to `"awaiting_semantic"` across all output formats (breaking: JSON consumers checking `evaluation` field need updating)
- "CLAUDE.md" replaced with "AI instruction files" in CLI, MCP, and setup strings

### GitHub Action improvements

- Agent default changed from `claude` to empty (resolve via project config or generic fallback)
- Added `-q` (quiet-semantic) flag for CI — no human to judge semantic rules
- Added `exclude-dir` input for comma-separated directory exclusions
- Fixed shell syntax error in step summary — JSON result passed via env var instead of shell argument

### Testing

Mutation-tested E2E smoke layer (`tests/smoke/`, 112 tests) covering agent scoping, cross-agent contamination, template context, hint messages, violation accuracy, CLI commands, mechanical checks, and flag combinations. Pipeline output stability tests with golden snapshots and regeneration flag. Unit test suite refactored — parametrized duplicates, added boundary/edge-case tests, relocated pure unit tests from integration/. GitHub Action regression workflow (`test-action.yml`) with pass/fail scenarios.

### Bug fixes

- `ails explain` did not resolve agent-namespaced rules (e.g., `CLAUDE:S:0001`) and showed "Unknown" for check labels — fixed in both CLI and MCP
- MCP tools (validate, score, heal) did not apply `exclude_dirs` from project config — was scanning all directories including test fixtures
- MCP `validate` handler missing `rules_paths` and `exclude_dirs` — called `run_validation` directly without resolving project config
- Semantic JudgmentRequests not deduplicated by file path — multiple D matches in the same file produced N evaluations instead of one
- Malformed YAML config files failed silently instead of logging warnings; malformed project config returned hardcoded defaults instead of global defaults
- Empty-files hint was hardcoded to CLAUDE.md instead of showing the correct instruction file per agent
- Unknown `--agent` values silently ignored — now error with exit code 2 and list known agents; values are case-insensitive
- Invalid `--format` values silently accepted — now error with exit code 2 and list valid formats
- `--agent generic` returned empty template context instead of file-derived vars
- JSON output serialized raw duplicate violations instead of deduplicated results
- Without `--agent`, scanned all agent files with identical rules instead of defaulting to generic
- Rule compiler crashed on `paths: include: null` in YAML rules (`dict.get()` returns `None` not default when key exists with null value)
- `exclude_dirs` config not applied during agent file discovery — test fixtures scanned as real instruction files
- `--refresh` flag only cleared semantic judgment cache, not agent or rule caches
- Mechanical checks ignored `rule.targets` — fell back to all instruction files instead of scoped targets
- `file_absent` searched from project root instead of rule target scope — project-level README.md triggered false violations for skills-scoped rules
- `disabled_rules:` with empty value in config.yml crashed with `TypeError` (`set(None)`)

### Dependencies

- Rules framework 0.5.0
- Recommended package 0.3.0
- Agent schema v0.2 compatibility

## 0.3.0

### Pure Python regex engine

Replaced the OpenGrep binary dependency with a pure Python regex engine. No external binary to download, no semgrepignore, no platform-specific builds. Includes an adversarial test suite (76 tests) validating edge cases. SARIF locations are now relative to the scan root instead of absolute paths.

### `ails heal` command

Interactive auto-fix and semantic evaluation. The auto-fix phase silently applies safe structural fixes (constraints, commands, testing sections, structure) via a registry of 5 additive fixers. Remaining semantic rules are presented for interactive pass/fail/skip/dismiss judgment. `--non-interactive` outputs JSON for coding agents and scripts. The MCP `heal` tool provides the same flow for editor integrations.

### `ails setup` command

Auto-detects agents in the project (Claude, VS Code, Codex) and writes MCP config files (`.mcp.json`, `.vscode/mcp.json`, `.codex/mcp.json`). Replaces the manual `claude mcp add` workflow. The npm wrapper now proxies `setup` instead of `install`/`uninstall`.

### GitHub Actions integration

Composite GitHub Action (`action/`) installs the CLI, runs validation, writes a step summary, and gates on score or violation count. `--format github` emits `::error`/`::warning` workflow commands for inline PR annotations.

### MCP overhaul

Validate tool returns structured JSON instead of formatted text. Semantic judgment requests carry full file content (up to 8KB) instead of 5-line snippets. Replaced the `_instructions` text blob with a structured `_semantic_workflow` object. Content-aware circuit breaker tracks file mtimes instead of a blunt call counter, allowing edit-validate cycles. Error responses use structured JSON with `error` and `message` keys. All tool descriptions rewritten with output format info and usage guidance.

### Performance

Agent detection, rule loading, glob resolution, and template binding are now cached across MCP invocations. Path-based pre-grouping avoids O(files × checks) inner loops. Combined regex patterns batch simple checks into alternation with named groups. Non-matching files are skipped before I/O. CSafeLoader used for YAML parsing when available (~3x faster).

### Bug fixes

- File discovery used project root instead of scan root — agent detection and feature scanning now scoped to target directory.
- Content rule violations attributed to root instruction file instead of skill files.
- Per-file size violations attributed to the violating file, not the rule-level target.
- Cache hash crash on non-UTF8 instruction files.
- Feature merge in capability detection used overwrite instead of OR.
- Regex compiler crash on malformed rule YAML and binary YAML files.
- Mechanical checks crash on string args from YAML.
- `detect_orphan_features` crash on L0 projects (no instruction files).
- `dismiss` command wrote to wrong cache when run from subdirectory.
- Double analytics recording — engine and check command both called `record_scan`.
- MCP tools: narrowed exception handling, added `is_dir()` validation, graceful file read errors.
- MCP judge: path-traversal rejection, detailed feedback, truncated reasons in response.
- Exit code 2 for input errors, exit 1 for violations.

### Dependencies

- Rules framework 0.4.0
- Recommended package 0.2.0

## 0.2.1

### Pipeline state engine

Rules now execute through a per-rule ordered check pipeline with shared mutable state. Deterministic+semantic rules run through a single regex pass, then SARIF results are distributed to per-rule buckets for ordered check execution. Includes in-memory check result cache for cross-rule mechanical dedup and D→M annotation propagation.

### MCP judge tool

Native `judge` MCP tool enables verdict caching directly from Claude Code, with a circuit breaker to prevent infinite validate-fix-validate loops.

### Module reorganization

Split 7 oversized modules (models, cache, registry, init, engine, checks, cli/main) to stay under pylint structural limits. Stricter tooling: ruff ARG/C90/PERF/RUF rules, pylint 300-line module enforcement.

### Security hardening

- Tarball extraction now validates all archive members for path traversal and symlink attacks before extracting.
- Rules update uses atomic swap: rename old out, move new in, restore on failure.
- Post-extraction structure validation ensures expected directories (`core/`, `schemas/`) exist.
- Path traversal fix in judgment cache writes.

### Bug fixes

- Pipeline silently swallowed unknown rule types instead of warning.
- Negated check_id lost full coordinate format (split on last colon instead of preserving `check:NNNN`).
- `content_absent` crashed on invalid regex patterns.
- Broad `except Exception` in frontmatter checks swallowed unexpected errors.
- `_apply_agent_overrides` mutated shared Rule objects (Rule now frozen).
- JSON serializer omitted `content` field from JudgmentRequest output.
- Nondeterministic directory selection in recommended extraction.
- explain_tool returned empty rules (missing paths + tier filtering).
- Template vars unresolved when engine uses custom rules_paths.
- Verdict parser mangled coordinate IDs with line numbers.
- MCP server crashed on RuntimeError from init/validation.
- ScanDelta IndexError on corrupted level in analytics cache.
- Concurrent judgment cache writes lost data (now atomic).
- Recommended rules download failures silently swallowed.
- `__version__` was hardcoded and drifted from package metadata.
- `_find_project_root` walked past child backbone into parent coordination root.

## 0.2.0

### CLI self-upgrade

New `ails update --cli` command upgrades the CLI package itself. Detects the install method (uv, pip, pipx) from package metadata and runs the appropriate upgrade command. Dev/editable installs are detected and refused with a helpful message.

`ails version` now shows the detected install method.

### Recommended rules included by default

Recommended rules (AILS_ namespace) are now included in every check and auto-downloaded on first run. The `--with-recommended` flag has been removed.

To opt out, add to `.reporails/config.yml`:

```yaml
recommended: false
```

`ails update --recommended` updates recommended rules only (skips framework).

### Unified update experience

`ails update` now updates both rules framework and recommended rules in a single command. Staleness detection tracks both components with a 24-hour cached check against GitHub releases.

Before each scan, the CLI prompts when updates are available: `Install now? [Y/n]`. CLI upgrades are shown as a hint but not auto-installed. Use `--no-update-check` to skip.

`ails update --check` shows installed vs latest for both framework and recommended. `ails version` displays recommended version alongside framework.

MCP tools (`validate`, `validate_text`, `score`) now include recommended rules in validation, matching CLI behavior.

### Mechanical checks

New rule type: mechanical checks are Python-native structural checks — file existence, directory structure, byte sizes, import depth, and more. Rules of any type may contain mechanical checks alongside deterministic patterns.

### Coordinate rule IDs

Rule IDs now use 3-part coordinate format (`CORE:S:0001`) instead of short IDs (`S1`). All commands (`explain`, `dismiss`) and config files (`.reporails/config.yml`) use the new format.

### Staging for rules download

`download_rules_version()` now extracts to a staging directory, verifies schema compatibility, then swaps. Incompatible rules no longer destroy working installations.

### `--exclude-dir` flag

`ails check --exclude-dir NAME` excludes directories from scanning. Repeatable for multiple directories.

### Release pipeline

Release workflow split into two stages: CI runs QA on version branches (e.g. `0.1.4`), and the release workflow triggers on merge to main — creating the tag, GitHub release, and publishing to PyPI and npm only after QA passes.

### Cache-busting for uvx

All `uvx` invocation strings now include `--refresh` to ensure users get the latest package version instead of a stale cache.

### Bug fixes

- Fix circular symlink detection crash on Python 3.12+ (`RuntimeError` instead of `OSError`).

### Dependencies

- Rules framework 0.3.1
- Recommended package 0.1.0
