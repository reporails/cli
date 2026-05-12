# Changelog

## 0.5.9

### Added

- Tooling: `uv run poe specs_check` validates internal subsystem coverage (declared subsystems exist, each spec is within line-budget, modules colocate under one subpackage); `uv run poe spec_drift` flags potentially stale design docs whose source has been edited more recently
- Tooling: expanded `pytest` marker taxonomy in `pyproject.toml` for granular test selection (lane, cost, subsystem) with new poe tasks `test_fast`, `test_arch`, `test_contracts`, `test_markers`
- Tooling: every `tests/*` test function now carries pytest lane (`unit`/`integration`/`e2e`) + subsystem (`subsys_*`) markers; `check_test_markers.py` enforces tagging on every `qa_fast` run, enabling `pytest -m subsys_caching` and similar slicing
- Tooling: hexagonal platform substrate skeleton bootstrapped at `core/platform/{contract,dto,policy,adapters,runtime,config,observability,utils}` with report-only architecture tests guarding pure-layer purity and adapter boundary (`tests/unit/architecture/`)

### Changed

- Build: bundle the `en_core_web_sm` spaCy pipeline (~15 MB) inside the wheel under `bundled/spacy/`, alongside the existing bundled ONNX embedder. `core/mapper/models.py` loads the pipeline by local filesystem path. End users no longer need a separate model download — `pip install reporails-cli` (or `uv pip install`, or `npx @reporails/cli`) delivers the full model bundle.
- Build: tightened `requires-python` to `>=3.12,<3.14`; Python 3.14 ships a `pydantic.v1` introspection regression that breaks `import spacy`. The CLI's verb-lexicon fallback covered the failure silently but with reduced precision. The pin restores spaCy classification under `uv sync`.
- API client: outgoing diagnostic requests now carry a `User-Agent: reporails-cli/<version>` header for accurate attribution in server-side logs; previously the generic `python-httpx/<version>` default was sent.
- Funnel: rate-limit CTA surfaces a "Try again in ~N min." hint when the server returns `reset_in`, between the limit blurb and the upgrade prompt.
- Funnel: CTA and bug-report URLs render as OSC 8 terminal hyperlinks with a short clickable label (`github.com/reporails/cli/issues/new`) instead of dumping the full percent-encoded prefilled URL; falls back to the short label on terminals without hyperlink support.
- Funnel: demoted the "Could not parse N response body" and "Server returned N for tier=" stderr warnings to debug logging so they no longer print above the diagnostic report; reworded the `unknown_error` CTA to `Diagnostics server returned HTTP <code>`.
- Display: file rows annotate duplicates with `(+alias)` labels — symlinked surfaces show the differing path component (e.g. `mintlify (+.claude)`), same-directory content-identical pairs show the alternate filename (e.g. `AGENTS.md (+CLAUDE.md)`).
- Internals: hexagonal platform substrate consolidated under `core/platform/{contract,dto,policy,adapters,runtime,config,observability,utils}`. Every top-level `core/*.py` moved into its appropriate layer (DTOs, adapters, runtime, etc.), with a new `core/install/` subsystem for installer-related modules. Architecture tests at `tests/unit/architecture/` run in fail mode — any forbidden cross-layer import blocks the build.
- Internals: five subsystems consolidated into named subpackages — `core/cache/`, `core/funnel/`, `core/classify/`, `core/heal/`, `core/discovery/`, `core/lint/` — each matching its design boundary.
- Internals: the mapper subsystem went the furthest. `core/mapper/mapper.py` was split into one module per pipeline stage (`imports.py`, `parse.py`, `classify.py`, `annotate.py`, `embed.py`, `cluster.py`, `assemble.py`) plus shared `models.py`, `serialize.py`, `inspect.py`. The orchestration spine retains the name `core/mapper/pipeline.py`. Public import surface (`map_ruleset`, `content_hash`, `map_file`) is unchanged; callers now import via the `core.mapper` package facade.
- Internals: removed the legacy "recommended" rules-overlay machinery from `ails config set/get/list`, `GlobalConfig`/`ProjectConfig`, and `core/install/`. User-installed rule packages remain supported through the generic `packages: [...]` mechanism in `.ails/config.yml` (clone any rule pack into `.ails/packages/<name>/` or `~/.reporails/packages/<name>/`).

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception
- Discovery: skill and rule files that appear under multiple agent surfaces via symlinks (e.g. `.claude/skills/` → `.agents/skills/`) are now collapsed to one canonical entry, eliminating duplicate findings and inflated scoring

### Removed

- CLI: removed `ails map`.

## 0.5.8

### Added

- [core/payload]: New `core/payload.py` module producing a compact wire payload for HTTP transport. Reduces request body size on large projects.
- [core/funnel]: New `WIRE_MAX_BYTES_BY_TIER` table and `preflight_byte_size()` function. Local preflight returns a `payload_too_large` `FunnelError` before transmission instead of an opaque server-side 4xx.
- [framework/rules/core/description-coherence]: New rule (`CORE:C:0055`) for files loaded on invocation (skills, subagents, slash commands) whose frontmatter `description:` doesn't match the body content. Server-execution rule. Replaces the previously-stale identifier the description-mismatch diagnostic had been pointing at (`prior-as-competitor`, an unrelated rule about default behavior competition).
- [core/funnel + formatters/text]: When the server returns an unrecognized error (`unknown_error` shape), the "Did you see an error?" exit ramp now deep-links to GitHub's new-issue form with the title, a triage-ready body (environment + reproduce skeleton), and a `bug` label prefilled — turning a generic `/issues` link into a one-click filed issue. Known funnel errors (rate limit, payload-too-large) keep the plain `/issues` index because they're usage signals, not bug reports.

### Changed

- [framework/rules]: Promoted `skill-name-matches-directory` to a cross-agent rule (CORE:S:0036). Skill `name` field must be kebab-case across every agent that loads `SKILL.md` entry points.
- [framework/rules]: Promoted `skill-no-readme` to a cross-agent rule (CORE:S:0035). Skill directories must keep all documentation in `SKILL.md` — a sibling `README.md` is never loaded.
- [framework/rules]: Promoted `skill-description-length` to a cross-agent rule (CORE:S:0040). The `description` field must be present in skill frontmatter; the open standard caps it at 1024 characters, with agent-specific caps acknowledged in the rule body.
- [framework/rules]: Promoted `import-depth-within-limit` to a cross-agent rule (CORE:S:0033) following the path-scope-declared supersede pattern. CORE carries a permissive absolute ceiling (max 10) as a sanity check; CLAUDE:S:0010 supersedes with Claude's documented 5-hop `@import` hard limit; CURSOR:S:0002 supersedes with `max: 1` reflecting Cursor's single-level `@filename` model. Codex and Copilot declare `CORE:S:0033` under `excludes:` in their `config.yml` because their instruction files do not honor `@<path>` syntax. Gemini inherits the CORE ceiling unchanged.
- [framework/rules/claude]: Renamed `memory-file-within-200-lines` to `memory-file-within-size-limit` (`CLAUDE:S:0011`) — slug no longer embeds the line number, since the threshold is fundamentally agent-defined. Stays in the CLAUDE namespace: Claude is the only agent with a dedicated `MEMORY.md` file the rule's `match: {type: memory}` can check (Gemini's memory is a section in `GEMINI.md`; Copilot's is system-managed with a 28-day TTL; Codex has none; Cursor's mechanic is undocumented). Promotion to CORE was reverted — it was forward-looking but in practice would have only fired on Claude.
- [framework/rules/claude]: Raised `rule-snippet-length` (`CLAUDE:S:0009`) threshold from 100 to 200 lines and dropped severity from `medium` to `low`. Added `see_also: [CORE:C:0044, CORE:S:0019]` cross-references — when a rule file follows topic-scatter and single-topic-per-section, 200 lines is comfortably enough.
- [framework/rules/copilot]: Renamed `applyto-scope-declared` to `path-scope-declared` for slug consistency with the cross-agent `path-scope-declared` family (Claude `paths:`, Cursor `globs:`, Copilot `applyTo:`). Rule body still describes Copilot's `applyTo:` mechanic; only the slug, title, and H1 heading change.
- [framework/rules/core]: Switched the `source:` URL for the three cross-agent skill rules (`skill-no-readme`, `skill-name-matches-directory`, `skill-directory-kebab-case`) from `code.claude.com/docs/en/skills` to `agentskills.io/specification`. The open standard is the canonical source for skill conventions; Claude's docs reflect the same conventions but aren't the universal reference.
- [core/api_client]: `_lint_remote` now sends the compact wire format by default.

### Fixed

- [core/classification]: Cross-agent rules with `match: {type: scoped_rule}` and `match: {type: skill}` now fire correctly. Agent configs use plural keys (`rules:`, `skills:`) for human readability while rule-side match expressions use the singular concept names; without aliasing, those rules silently never matched any file. A `_FILE_TYPE_MATCH_ALIASES` map applied at `ClassifiedFile` construction normalizes the surface key to the match vocabulary while preserving the literal key for `surfaces.<agent>.<file_type>` lookup. Bandage solution — the proper fix is to align vocabulary in one direction (either agent configs use singular keys or rule-side `match.type` uses plural). Tracked as a follow-up.
- [core/agent_discovery]: `surfaces.<agent>.<file_type>.exclude` patterns now apply across every surface of the agent, not just the surface they were declared on. Two surfaces of the same agent commonly share patterns (e.g. `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`) — declaring an exclude on one previously left the file surfaced from the other. Discovery now collects the union of all per-surface excludes for the agent and applies it once per surface.
- [formatters/text/scorecard]: `compute_surface_scores` relativizes `ruleset_map.files[*].path` against the project root before classification. Absolute paths from the mapper were being tagged `nested` purely because their leading filesystem components inflated the `parts` count, so a project with one root-level `CLAUDE.md` was rendered as `Main (1) ... Nested (1)`. Findings (which already carry relative paths) and the mapper's file list now classify consistently.
- [interfaces/mcp]: Updated `explain` tool example coordinate from `CLAUDE:S:0011` (promoted/renamed) to `CLAUDE:S:0005` so the MCP tool description references a current rule.
- [core/mapper/daemon]: Mapper daemon's 1-hour idle timeout is now opt-in via the `AILS_DAEMON_IDLE_S` env var instead of applied by default. Without the override the daemon stays running until `ails daemon stop` or an explicit kill — matching the user expectation that "background" means "doesn't go away on its own". The previous 1-hour default caused the daemon to terminate between dev sessions, so each subsequent `ails check` paid the cold-start cost.
- [framework/rules/core]: Four server-driven diagnostics that displayed unrelated rules via `ails explain` are now pointed at coherent rules. `description-mismatch` → new `CORE:C:0055` `description-coherence` (was the unrelated `prior-as-competitor`). `overall-strength` → `CORE:C:0053` `ideal-instruction`, the existing composite-rollup rule whose own Limitations describes it as such (was `compound-weakness`, which is per-atom multiplicative, not file-level). `named-coverage` → `CORE:C:0042` `specificity-gap` (was `specificity-shields`, which scopes itself to prose-heavy files; the diagnostic fires regardless of prose). `orphan` stays at `CORE:C:0053` (the existing mapping was correct — `ideal-instruction` Fix bullet #3 names the golden pattern explicitly). Also dropped two dead `RULE_ID_MAP` entries (`cross-conflict`, `cross-repetition`) that were never reachable — cross-file findings carry their own `finding_type` and never go through the diagnostic-label translation.

## 0.5.7

### Added

- [framework/schemas/project.schema.yml]: New `surfaces` and `agents` keys for `.ails/config.yml`. `surfaces.<agent>.<file_type>.include` / `.exclude` adjusts which globs each agent surface scans without modifying bundled configs. `agents.<id>.fallback_filenames` mirrors Codex `project_doc_fallback_filenames` so per-project alternative instruction filenames (e.g. `TEAM_GUIDE.md`) are picked up by the validator.
- [core/config]: `.ails/config.local.yml` (gitignored) layers on top of committed `.ails/config.yml` for personal/CI overrides — object keys merge recursively, array keys extend, scalars replace.
- [interfaces/cli/config_command]: `ails config set` writes `.ails/.gitignore` listing `.gitignore` itself and `config.local.yml` whenever `.ails/config.yml` is created/updated, so layered local config stays out of version control by default.
- [framework/rules]: `nested_context` declarations for codex / cursor / copilot / generic agents so per-package `**/AGENTS.md` files in monorepos are surfaced under the agent's on-demand loading model rather than skipped.
- [formatters/text]: Surface classifier distinguishes `main` (root-level instruction file) from `nested` (subdirectory copies). Scorecard shows a separate "Nested" section; nested file paths display the full relative path (`packages/web/CLAUDE.md`) so users can locate them.

### Changed

- [framework/schemas]: Added `scope: nested` to the `agent.schema.yml` and `rule.schema.yml` enums. Captures surfaces whose subtree applicability comes from file LOCATION (subdirectory CLAUDE.md / AGENTS.md / GEMINI.md) rather than from in-file frontmatter. Replaces the previous overload of `scope: path_scoped` for these surfaces.
- [core/agent_discovery]: Project root for `ails check <path>` is now `<path>` itself — no walking up. Files outside the targeted subtree are out of scope, regardless of `.git` or `.ails/backbone.yml` location. `engine_helpers._find_project_root` continues to walk up for cache key derivation only and now also recognizes IDE workspace markers (`.vscode/`, `.idea/`, `.github/`) as project-root signals.
- [core/agent_discovery + core/agents]: Filename matching for agent instruction files is now case-sensitive, matching Codex's source (`codex-rs/core/src/agents_md.rs` — `DEFAULT_AGENTS_MD_FILENAME = "AGENTS.md"`, `LOCAL_AGENTS_MD_FILENAME = "AGENTS.override.md"`) and the agents.md spec. A file named `agents.md` (lowercase, no leading dot) is no longer falsely surfaced as a Codex AGENTS.md candidate.
- [framework/rules/cursor]: `cursor.rules` corrected to `scope: path_scoped` (frontmatter-based path filtering); `cursor.bugbot_rules` to `scope: global` (BugBot decides applicability).

### Fixed

- [core/classification + core/agent_discovery]: Instruction-file discovery and classification now correctly distinguish `main` files at the user's target from `nested_context` / `child_instruction` files in subdirectories. Per-package CLAUDE.md / AGENTS.md / GEMINI.md files in monorepos are classified as `nested_context` rather than `main`, so size and other `match: {type: main}` rules no longer false-positive on per-package nested files. Bug surfaced against [activepieces/activepieces](https://github.com/activepieces/activepieces).
- [core/registry]: `depends_on` resolves through supersession. When `CODEX:S:0003 supersedes CORE:S:0027`, rules that depend on `CORE:S:0027` (e.g., `CORE:S:0030`, `CORE:G:0006`) are satisfied by `CODEX:S:0003` instead of warning that the dependency is "not loaded". `_apply_supersession` returns a `{superseded_id: successor_id}` map; `_validate_depends_on` consults it before emitting the missing-dependency warning.
- [core/classification]: `_location_matches_mode` distinguishes "loose" leaf patterns (`**/CLAUDE.md`, bare `CLAUDE.md`) from "tight" path-prefixed patterns (`.github/copilot-instructions.md`). Path-prefixed patterns already constrain location via the prefix, so the ancestor-chain check is skipped — fixes false-negative classification of Copilot's `.github/copilot-instructions.md`.
- [tests/unit/test_scan_scope]: `test_codex_fallback_filenames_surface` now creates `.codex/config.toml` in the fixture so codex passes the codex/generic disambiguation deterministically — was HOME-dependent (locally `~/.codex/` let codex through, fresh CI runners without `~/.codex/` dropped codex and the fallback patterns never fired).

## 0.5.6

### Added

- [docs]: Public documentation under `cli/docs/` — index, getting-started, agent-support, configuration, tiers, score-guide, faq. Vocabulary uses anonymous vs. signed in throughout (replaces earlier Pro / Free / paid framing). Maturity-levels and MCP integration pages dropped — both deferred until their respective redesigns land.
- [docs/tiers]: New page — side-by-side capability table for anonymous vs. signed-in mode, what each limit means in practice, illustrative output for both modes plus the rate-limit assessment-box CTA, and the sign-in flow (`ails auth login` → `ails auth token`). Replaces the inline "Free vs Pro" matrix that used to live in `README.md`.
- [action]: `api-key` and `server-url` inputs on the GitHub Action wrapper, passed through to the `ails check` step as `AILS_API_KEY` / `AILS_SERVER_URL` env vars — enables authenticated full diagnostics in CI.
- [pre-release]: Config + README sync step in `scripts/pre-release-check.sh` (`check-config-sync.sh`) — fails the release when `pyproject.toml` and `packages/npm/package.json` diverge on shared metadata (version, description, keywords, homepage, bug tracker, repository) or when the README's first heading is missing the version label `(vX.Y.Z)`.
- [framework/rules/claude]: `scheduled_tasks` file_type pointing at `~/.claude/scheduled-tasks/**/SKILL.md`.
- [framework/rules/claude]: `Setup` event added to `hook-valid-event-types` regex (29 total events, was 28).
- [core/funnel]: New module — `FunnelError`, `LintResponse`, `parse_error_body`, `preflight_oversized`, `merge_utm`, `format_cta`. Centralises the conversion-funnel error shape so server 4xx bodies and local preflight rejections render the same assessment-box CTA.
- [formatters/text]: Assessment-box renders a tier-and-error-aware CTA when a `FunnelError` is present. UTM-tags every CTA URL via `merge_utm`. A secondary "Did you see an error? Let us know: <BUG_REPORT_URL>" line renders below the upgrade CTA so failures always carry an exit ramp to GitHub issues.
- [core/api_client]: Universal-cap preflight (atom / file / cluster counts) saves an HTTP round-trip when the payload would be hard-rejected regardless of tier.
- [core/api_client]: Empty-files short-circuit. When the mapper returns no instruction files, `_lint_remote` skips the HTTP round-trip.
- [tests/unit/test_funnel]: Unit tests covering `parse_error_body`, `preflight_oversized`, `merge_utm`, `format_cta`, and `LintResponse`.
- [tests/unit/test_api_client]: `test_lint_skips_http_when_no_files` — regression guard for the empty-payload short-circuit.
- [auth_command]: `ails auth token` subcommand. Prints the stored API key to stdout for CI export — pipes cleanly into `AILS_API_KEY=$(ails auth token)`. Exits non-zero when not authenticated so scripts can detect missing credentials.
- [CONTRIBUTING.md]: New community-health file with contribution preamble.

### Changed

- [framework/rules/gemini]: `hook-handler-has-type` regex tightened to `command` only — Gemini docs explicitly state `prompt` is not a supported hook type.
- [framework/rules/copilot]: `hook-handler-has-type` regex tightened to `command` only — VS Code Copilot docs explicitly state `prompt` is not a supported hook type.
- [framework/rules/copilot]: `hook-valid-event-types` regex reduced to the 8 PascalCase events documented by VS Code Copilot.
- [framework/rules/cursor]: `hook-valid-event-types` rule narrative corrected from "18 events" to "20 events" — regex already covers the full 20-event Cursor set per `cursor.com/docs/hooks`.
- [core/funnel]: Conversion-CTA messages reflect the operational two-tier model. Anonymous CTAs point at `ails auth login`; signed-in CTAs route to GitHub issues for use-case escalation.
- [README.md]: Trimmed to elevator-pitch length — Quick Start, showcase output, install permanently, anonymous vs signed, In CI, doc links.
- [packages/npm/README.md]: Replaced the duplicate file with a symlink to root `README.md`.
- [pre-release-check]: New `Branch ↔ version alignment` gate — if the HEAD branch is named `X.Y.Z`, `pyproject.toml` version must equal the branch name.

### Verified

- [framework/rules/codex]: Hook regexes audited against `developers.openai.com/codex/hooks`. `hook-handler-has-type` (`type: command` only) and `hook-valid-event-types` (6 events) match the docs.
- [framework/rules/cursor]: `hook-handler-has-type` (`type: command|prompt`) confirmed against `cursor.com/docs/hooks`.
- [framework/rules/core]: Category audit run across all 91 CORE rules — 76 OK, 15 reclassifications deferred to a dedicated session.

### Fixed

- [pyproject]: `Documentation` URL no longer points at a 404. Now points at the GitHub README until the rule listing is published.
- [docs/credential-storage]: Removed the factually wrong "credentials are stored in your OS keyring" claim from `docs/faq.md`, `docs/tiers.md`, and `docs/configuration.md`. Actual storage is `~/.reporails/credentials.yml` with `chmod 0600` on POSIX.
- [core/api_client]: Preflight check rejects oversized payloads (`files`, `atoms`, `clusters`) before the HTTP round-trip.
- [core/api_client]: 4xx response bodies are now parsed and surfaced via a `LintResponse` envelope with either `.result` or `.funnel_error`.

### Removed

- [VERSION]: Deleted the orphan `cli/VERSION` file. `pyproject.toml` is the source of truth.

## 0.5.5

### Added

- Rules: Populate `backed_by` source IDs on CORE rules from `docs/sources.yml` (research evidence references)
- Rule layering: `inherited` field — child accumulates parent checks without replacing parent
- Rule layering: `depends_on` field — declare execution ordering with circular dependency detection
- Path validation: `CLAUDE.S.0012.paths_resolve` check — verifies frontmatter globs match actual files
- Schema: `source` field (URI) on rules — links to the official agent documentation a rule enforces
- Rules: CORE:S:0026 `import-references-used` — verify `@path` imports resolve to existing files
- Rules: CORE:G:0003 `permissions-ordered` — permission configuration must be present in settings
- Rules: CORE:C:0037 `static-before-dynamic` — separate stable from dynamic content with headings
- Rules: CORE:S:0031 `skill-file-length` — 500-line ceiling on `SKILL.md` files
- Rules: 22 hook rules — 5 CORE base rules with `depends_on` chain, plus agent-specific overrides for Claude, Codex, Copilot, Cursor, and Gemini
- Registry: Add `hooks` file_type to Claude config — hooks are a distinct surface from config

### Changed

- Checks: `frontmatter_valid_glob` reads `applyTo` frontmatter key for Copilot scope validation
- Schema: Migrate `Check`, `Rule`, `FileMatch`, `FileTypeDeclaration`, `ClassifiedFile` from dataclasses to Pydantic models
- Schema: `rule.schema.yml` v0.7.0 → v0.8.0 — added 9 missing check functions, `inherited`, `depends_on`, check-level `replaces`/`severity`/`message`
- Schema: Remove `overrides` from `agent.schema.yml` — severity overrides are a project-level setting
- Project: Fix stale `docs/specs/` references in `backbone.yml`, `CLAUDE.md`, `discover.py`
- Rules: Fix type mismatches in CORE:S:0018, CORE:S:0022; missing args in CLAUDE:S:0003
- Rules: Downgrade CORE:S:0017 `self-contained-skills` to low severity, accept alternative heading names
- Rules: Downgrade CORE:S:0022 `local-override-file` to low severity (override file is optional)
- Rules: 5 Claude hook rules rewritten — recognized event names, handler types, and `$CLAUDE_PROJECT_DIR` use
- Rules: Renamed Claude skill slugs and Codex slugs (clean names replace sentence fragments)
- Rules: 12 project-level CORE rules narrowed to `match: {type: main}` — fixes false positives on agent and skill files
- Sources: Move official agent documentation references from `backed_by` into per-rule `source` URLs
- Registry: Fix Claude memory cardinality `singleton` → `collection`, add rules domain field
- Repo hygiene: Add `.ignore` at repo root so Claude Code does not index test fixtures as real configuration
- CI: Add `windows-latest` to CI matrix — run lint, type check, and tests on both Ubuntu and Windows
- Tests: Skip symlink tests on Windows (require admin/Developer Mode)

### Fixed

- Regex engine: Replace POSIX-only `signal.SIGALRM` timeout with cross-platform `_timeout_guard` context manager — fixes `AttributeError` crash on Windows (#17)
- Daemon: Add `sys.platform` guards to `start_daemon`, `stop_daemon`, and daemon client for `os.fork`/`fcntl`/`AF_UNIX` — clear error message on Windows instead of raw `ImportError`
- Auth: Guard `chmod(0o600)` on credentials file — warn on Windows where NTFS ACLs don't support mode bits
- Self-update: Fix ephemeral install detection to check Windows `uv\tools\` path
- Rules: Fix double-negation patterns in 5 Claude hook rules (`expect: absent` + `pattern-not-regex` → `expect: present` + `pattern-regex`)
- Rules: Fix broken `byte_size` check on CLAUDE:S:0003 — replaced with `description` field presence check

### Removed

- Remove CORE:M:0001 `freshness-marker` — no agent documentation supports it

## 0.5.4

### Added

- Per-surface health scores with file counts in scorecard
- Rule inheritance via `supersedes` — agent rules inherit and optionally replace CORE checks
- Check-level `replaces`, `severity`, `message` override fields; `Severity.LOW` and `Severity.INFO` levels
- `frontmatter_extra_keys` mechanical check — warns when frontmatter has keys the agent ignores
- CLAUDE:S:0012 path-scope-declared — detects `globs:` misuse, enforces `paths:` as the correct key
- CURSOR:S:0001 and COPILOT:S:0001 path-scope-declared with `supersedes: CORE:S:0038`

### Fixed

- Charge classifier misses for `append`, `stage`, `compose` and 5 other verbs; ambiguous/nsubj verb rescue at position 0
- Quote-scope-aware sentence splitting — don't split inside quoted or parenthetical spans
- Backtick filter false positives on position-0 verbs appearing in later backtick spans
- M-probe pipeline skipped deterministic checks in mixed-type rules; mechanical and deterministic checks now use `match_files()` for full property-based targeting
- Show progress output during mapper startup — fixes silent hang on projects with instruction files
- Add default `exclude_dirs` to prevent walking massive non-instruction trees
- CORE:S:0038 made agent-agnostic with plain test fixtures

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

Scorecard moved to bottom of output — violations shown first, score as conclusion. Category table redesigned with mini bars, centered columns, and severity-colored icons. Maturity level moved to own line below score, elapsed time shown in top-right. Semantic color output throughout — score, bar, level, violations, friction, and category table use green/yellow/red (ASCII mode disables colors). Pending semantic checks shown inline with violations using `?` icon. "Setup:" replaced with "Scope:" showing instruction files by agent directory labels.

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
- Feature merge in agent feature lookup used overwrite instead of OR.
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
