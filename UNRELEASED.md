# Unreleased

### Breaking Changes

- [LEVELS]: Rename labels (Organized→Structured, Distributed→Substantive, Contextual→Actionable, Extensible→Refined, Governed→Adaptive)
- [MODELS]: Replace `Rule.targets` string with `Rule.match` (FileMatch dataclass)
- [MODELS]: Add FileTypeDeclaration, ClassifiedFile, FileMatch dataclasses
- [MODELS]: Rename level labels
- [AGENTS]: Reduce supported agents to 4 (claude, copilot, codex, generic)
- [MECHANICAL]: Replace vars dict with ClassifiedFile list in all check signatures
- [MODELS]: `Check` dataclass no longer has `severity` or `name` — severity is now a rule-level field on `Rule`
- [RULES]: `rule.yml` renamed to `checks.yml` with `checks:` top-level key; checks consolidated from rule.md frontmatter

### Added

- [CORE]: `core/equation.py` — server-side diagnostics engine running per-atom and interaction analysis on `RulesetMap`. Returns categorical compliance bands for user-facing output.
- [CORE]: `core/equation_hints.py` — free/pro tier gating: per-atom diagnostics pass through on both tiers, interaction diagnostics become aggregated hints on free tier
- [CORE]: `Hint` and `LintResult` dataclasses in `api_client.py` — `Hint` carries aggregated interaction summaries for free tier, `LintResult` wraps report + hints + tier
- [CORE]: `core/_torch_blocker.py` — `sys.meta_path` import hook installed at CLI, MCP server, and daemon child entry points. Raises `ImportError` for any `torch*` import, cleanly triggering thinc's `except ImportError: has_torch = False` fallback and eliminating the ~20s cold-start cost that was previously leaking in through `spacy → thinc → try: import torch`. The reporails pipeline does not need torch at runtime.
- [CORE]: `core/mapper/onnx_embedder.py` — `OnnxEmbedder` class replaces `sentence-transformers` on the encode path. Loads a bundled `all-MiniLM-L6-v2` ONNX export (fp32, bit-identical to the PyTorch reference at float32 epsilon) via `onnxruntime` + `tokenizers`, no torch dependency. Includes length-sorted bucketed batching (bs=16) for tight dynamic padding — +28% throughput on real atoms.
- [BUILD]: `scripts/fetch_bundled_model.py` — idempotent dev-only helper that populates `src/reporails_cli/bundled/models/minilm-l6-v2/` from `Xenova/all-MiniLM-L6-v2` on Hugging Face Hub. Runs on clone and in CI before `hatch build`. Also exposed as `uv run poe fetch_bundled_model`.
- [BUNDLED]: `bundled.get_models_path()` helper, parallel to `get_project_types_path()`, used by `OnnxEmbedder` to locate the bundled ONNX weights inside the installed wheel.

- [MCP]: Compact response format — violations grouped by file, short-key judgment requests, whitespace-free JSON
- [MCP]: Explain returns readable text instead of JSON; judge returns text summary
- [MCP]: Inline semantic workflow instructions in validate/heal tool descriptions
- [CLI]: Add `agent` output format (`ails check -f agent`) — compact JSON matching MCP format
- [JSON]: Add `scope` field to explain output (from rule match criteria)
- [AGENTS]: Three-tier codex/generic disambiguation (AGENTS.override.md → .codex/config.toml → global heuristic)
- [AGENTS]: `detect_single_agent()` for explicit --agent bypass of disambiguation
- [BOOTSTRAP]: Add `get_framework_root()` for framework metadata access
- [BUNDLED]: Absorb rules, schemas, registry, and sources.yml from rules repo into CLI as bundled content (~342 files)
- [BUNDLED]: Add `bundled.py` module — zero-install rules resolution via `importlib.resources` with dev-mode fallback
- [BUILD]: Add `force-include` in pyproject.toml to bundle rules/schemas/registry/sources.yml into wheel
- [BUILD]: Consolidate rule content under `framework/` at repo root
- [BUILD]: Add hatch build hook to exclude test fixtures from wheel — ships only rule.md, checks.yml, config.yml
- [BUILD]: Trim wheel — remove schemas/ and unused registry files (only levels.yml is runtime)
- [HARNESS]: Add `ails test --lint` — structural integrity checks on rule files (ID↔category, check ID prefix, duplicates, required frontmatter)

- [CORE]: `core/mapper/` — 7-stage mapper pipeline (parse, classify, annotate, embed, cluster, assemble)
- [CORE]: `core/client_checks.py` — D-level checks (charge ordering, orphans, format, scope, bold)
- [CORE]: `core/api_client.py` — server client stub with offline fallback
- [CORE]: `core/merger.py` — merge local + server findings into `CombinedResult`
- [CORE]: `core/rule_runner.py` — iterate YAML rule definitions, dispatch mechanical + deterministic checks
- [MODELS]: `LocalFinding` dataclass for pipeline-native findings
- [CORE]: `core/mapper/map_cache.py` — per-file atom+embedding cache keyed by content hash
- [CORE]: `core/mapper/daemon.py` — persistent background process keeping sentence-transformers model loaded
- [CORE]: `core/mapper/daemon_client.py` — Unix socket client with graceful fallback
- [CLI]: `ails daemon start|stop|status` — manage mapper daemon lifecycle

### Fixed

- [CORE]: Wire detected agent into `load_rules()` and `load_file_types()` — agent-specific rules (CLAUDE:S:*, COPILOT:*, CODEX:*) now load during `ails check` and MCP validation. Previously only CORE rules were checked. `load_file_types()` fallback changed from hardcoded `"claude"` to `"generic"`.
- [CLI]: Add `--agent` and `--exclude-dirs` options to `ails check`. Agent resolves from CLI flag → project config (`default_agent`) → auto-detection. Shows auto-detect hint when agent was assumed.
- [BUNDLED]: Move generic agent config from `framework/rules/generic/` into `framework/rules/core/config.yml`. `get_agent_config_path("generic")` now resolves to `core/config.yml`.
- [BUNDLED]: Remove unsupported agent directories (aider, cline, continue, roo, windsurf). 6 agents remain: claude, codex, copilot, cursor, gemini, generic.
- [BUNDLED]: Codex config no longer claims AGENTS.md as exclusive `main` file. AGENTS.md is a cross-agent standard — its presence alone detects as `generic`. Codex detection requires `.codex/` markers or `AGENTS.override.md`.
- [CORE]: Derive agent membership from `FileRecord.agent` (populated from agent config registry) instead of hardcoded path patterns in `equation.py`. Eliminates duplication between agent configs and equation-layer detection. Case-insensitive matching; specificity-based disambiguation when multiple agents match (longest literal prefix wins).
- [CORE]: Fix daemon JSON round-trip dropping `scope_conditional` and `plain_text` from Atom — caused silent divergence between daemon and in-process mapping output (4 client-check findings missing on this repo)
- [CORE]: Fix double-embedding in `cluster_topics()` — was re-encoding all atoms instead of using pre-computed `embedding_int8` (162s → 3.5s with daemon)
- [CLI]: Fix Rich `MarkupError` — severity values like `medium`/`high` and bracket characters in rule IDs crashed the text formatter
- [REGEX]: Fix `run_checks()` expect semantics — was reporting matches as violations for `expect: present` rules (inverted logic)
- [CLI]: Group findings by topic in text output — uses human-readable `heading_context` labels from mapper clusters
- [CORE]: Normalize file paths in `client_checks` to project-relative for display consistency
- [REGEX]: Fix `run_checks()` duplicate reporting — was processing mechanical checks as regex (390 empty-message findings eliminated)
- [CLI]: Merge topic display by `heading_context` — multiple clusters under the same heading now show as one topic
- [CORE]: `core/content_queries.py` — atom-based content-quality queries (replaces regex text scanning)
- [CORE]: `core/content_checker.py` — dispatches `type: content_query` checks against `RulesetMap`
- [BUNDLED]: 25 content-quality rules migrated from deterministic regex to `content_query` atom checks (deterministic retained as `fallback: true`)
- [MODELS]: `Check` dataclass adds `query`, `fallback` fields for content_query check type

- [STOPWORDS]: Add `ails stopwords extract` — parse checks.yml alternation patterns into vocab.yml term lists
- [STOPWORDS]: Add `ails stopwords sync` — compile vocab.yml terms back into checks.yml patterns (with `--dry-run`)
- [STOPWORDS]: Add staleness detection for vocab.yml vs checks.yml drift

- [PROJECT]: Rename project-level `.reporails/` to `.ails/` — aligns with CLI command namespace, sorts first in dotfolders

### Removed

- [CORE]: Remove `equation.py` and `equation_hints.py` — diagnostics are server-only via API
- [CLI]: Remove `batch.py` — internal research tool, not part of the published CLI
- [CORE]: Scrub experiment IDs, effect sizes, and theory notation from code comments
- [CORE]: Rename `CAPABILITY_DETECTORS` → `FEATURE_DETECTORS` in `levels.py`
- [BUNDLED]: Remove deferred rules (freshness-marker, import-references-used, permissions-ordered, static-before-dynamic) and archived manifest rule
- [DOCS]: Update README and npm README with current output format and package names
- [BUILD]: Remove dead `download_rules` step from CI/release workflows. Add `NODE_AUTH_TOKEN` to npm publish.
- [BUILD]: Update `pyproject.toml` and `package.json` descriptions to "AI instruction diagnostics for coding agents"
- [CORE]: `agents.py` — `_extract_patterns()` and `_extract_properties()` helpers support both v0.3.0 (patterns + properties nested) and v0.5.0 (scopes with patterns, properties flattened) agent config schemas. All pattern/property extraction uses these helpers.
- [CORE]: `classification.py` — `_parse_file_types()` updated for v0.5.0 schema compatibility
- [CORE]: `mapper.py` — `_detect_file_loading()` updated for v0.5.0 schema compatibility
- [AGENTS]: All agent configs updated to v0.5.0 schema with scopes structure (project/user/managed/local)
- [FORMATTERS]: Archive `full.py`, `box.py`, `violations.py`, `compact.py` to `_archived/formatters/` — dead code since CombinedResult pipeline replaced ValidationResult rendering. Tests archived alongside.
- [CORE]: Pipeline orchestration (`engine.py`, `pipeline.py`, `pipeline_exec.py`, `sarif.py`) — replaced by `rule_runner.py`
- [CORE]: Semantic layer (`semantic.py`) — equation replaces LLM-as-judge
- [CORE]: `content_linter.py`, `excitation_map.py`, `scorer.py`, `topo_scanner.py` — replaced by mapper + client checks
- [CLI]: Remove `heal`, `sync`, `update`, `topo`, `lint`, `dismiss`, `judge` commands
- [MCP]: Remove `judge` and `heal` tools
- [BUNDLED]: 6 FALSIFIED rules, 4 BEHAVIORAL rules, 4 M3-SUPERSEDED rules
- [BUNDLED]: Semantic check entries from 12 surviving rules, content quality patterns from 4 rules

### Changed

- [CLI]: Scorecard redesign — score with bar, agent, scope (capabilities + instruction breakdown), and results at bottom of output where users land after scrolling. Tier badge in header. Beta CTA for unauthenticated users.
- [CORE]: `api_client.py` — remove local equation fallback. Diagnostics are API-only; CLI never imports `equation.py` at runtime. Offline users get mechanical checks only.
- [CORE]: `equation.py` — strip internal distance metric from description-mismatch diagnostic message
- [AGENTS]: `_disambiguate_shared_files()` in `detect_agents()` — drop agents whose instruction files are entirely shared with other agents (e.g., AGENTS.md matching 5 agents). Fixes 38% corpus over-classification.
- [CORE]: `equation.py` — opposing instructions within the same topic now subtract instead of reinforce in the diagnostics engine
- [CORE]: `equation.py` — topic count uses semantic distance merge threshold; returns distinct group count after merging instead of largest connected component
- [CORE]: `equation.py` — cross-file diagnostics scoped to shared topic clusters only, with semantic distance threshold within each cluster
- [CORE]: `equation_hints.py` — free tier preserves severity on hints and compliance band; interaction diagnostics are detail-gated (no lines/fixes) but error counts and compliance band are shown honestly
- [CORE]: `api_client.py` — `Hint` dataclass adds `severity`, `error_count`, `warning_count` fields for exact severity counts from gated diagnostics
- [CORE]: `rule_runner.py` — deterministic checks now grouped by `rule.match.type` and run against matching files only; rules with `match: {type: scoped_rule}` no longer fire on `main` files (CLAUDE.md). Eliminated ~215 false positive findings
- [CORE]: `merger.py` — `normalize_finding_path()` unifies file paths from all three sources (m_probe, client_check, server) to project-relative. External files (auto-memory) normalize to `~/`. Eliminates path fragmentation that caused the same file to appear under multiple keys in JSON output (60+ → 31 file keys)
- [CLI]: Free tier summary now shows error count, compliance band, and severity icons on hints
- [CORE]: `mapper.py` — position-0 verb rescue in `_classify_phase3_spacy`: rescues demoted imperative verbs (csubj/compound/nmod/dep) as IMPERATIVE (+33 rescued atoms on this codebase)
- [CORE]: `mapper.py` — `_split_mixed_charge_atoms` no longer skips neutral atoms: compound sentences with embedded charge ("You are X. Never do Y.") now split correctly
- [CORE]: `mapper.py` — AMBIGUOUS charge type: two-pass neutral scanner flags atoms with embedded constraint/directive markers in descriptive context (charge_confidence=0.0). 21 atoms flagged on this codebase
- [CORE]: `mapper.py` — `_rule_confidence()` maps classifier rule traces to confidence tiers (0.95/0.80/0.60/0.70)
- [CORE]: `equation.py` — AMBIGUOUS atoms excluded from diagnostics analysis; dedicated diagnostic emitted per AMBIGUOUS atom
- [CORE]: `equation.py` — neutral mass diagnostic reworded from "too much prose" to "uncharged items dilute instructions" — sub-bullets and references are not prose
- [CORE]: `mapper.py` — headings classified through charge pipeline (headings ARE content). `## Never push to main` now gets charge=-1. Validator updated.
- [CORE]: `mapper.py` — `_embed_text()` no longer prepends heading context. Removes double-counting (heading exists as own atom). Clustering by semantic content, not heading structure.
- [CORE]: `equation.py` — heading atoms now participate in diagnostics analysis (removed heading exclusion filters)
- [CORE]: `equation.py` — specificity diagnostic only fires when file contains abstract instructions. Message changed to "name constructs" not "split files"
- [CORE]: `mapper.py` — heading atoms now embedded (were skipped). Classified headings now participate in diagnostics analysis, conflict detection, and topic computation.
- [CORE]: `client_checks.py` — new check: instruction in heading. Flags charged heading atoms as structural hygiene issue — headings should organize, not instruct. Also: bold check now includes heading atoms.
- [RULES]: New rule `heading-as-instruction` (CORE:S:0039) — proper rule with checks.yml, content_query `has_charged_headings`, and test fixtures
- [CORE]: `mapper.py` — emit `code_block` atoms from fence tokens (was skipping them entirely, making `has_code_blocks` a dead query)
- [CORE]: `content_queries.py` — add `has_non_italic_constraints`, `has_mermaid_blocks`, `has_branching_steps` content queries
- [CORE]: `client_checks.py` — bold label exception: `**Label**:` patterns (bold + colon) skipped as structural labels
- [CLI]: `ails batch <corpus-dir> --output-dir maps/` — run full check pipeline on every project in a corpus. Models loaded once. Per project writes `ruleset.json` (RulesetMap) + `lint.json` (equation diagnostics). Summary JSONL for aggregation.
- [CLI]: `ails heal [PATH] [--dry-run] [-f json]` — auto-fix instruction file issues. Mechanical fixers: backtick wrapping, bold→italic on constraints, full-sentence italic, charge ordering. Additive fixers: missing sections.
- [CORE]: `core/mechanical_fixers.py` — 4 atom-level fixers operating on raw file content via RulesetMap. Italic fixer skips lines with existing italic spans to prevent nesting.
- [MCP]: `heal` tool for auto-fixing instruction file issues
- [CLI]: Redesigned text output — "Reporails — Diagnostics" header with file type breakdown, instruction counts (directive/constraint/ambiguous), prose density. Files grouped by type in bordered cards. Structural findings (M1/M2) display first, quality metrics (M3) aggregated below in dim. Per-file identity by friendly name. Messages truncate at terminal width. All server diagnostics now aggregate.
- [CORE]: Reword topic diagnostic — "N overlapping topics (out of M)" instead of "competing for attention". No IP leakage.
- [CORE]: Three-way cross-file co-visibility model: base (main+rules) ↔ inline_invoked (skills+commands) ↔ agent_def. Agent↔skill and skill↔skill pairs compared (co-visible via Skill tool). Agent↔agent skipped (subprocess-isolated).
- [CORE]: `equation.py` — topic competition uses semantic distance — distant topics no longer trigger false positives. Only flags when topics are within range.
- [CORE]: `mapper.py` — `FileRecord` gains `description` and `description_embedding` fields. Frontmatter name+description extracted and embedded for on_invocation files (always in base context per Agent Skills standard).
- [CORE]: `equation.py` — description-content coherence diagnostic: flags on_invocation files whose frontmatter description doesn't match content semantically.
- [CORE]: `equation.py` — description competition: skill/agent descriptions in base context included in topic competition for base files.
- [CORE]: `equation.py` — memory index validation: broken links (error), missing frontmatter (warning) in MEMORY.md index files.
- [CORE]: `client_checks.py` — remove directive-only orphan diagnostic. Golden pattern is +1,0 (directive+reasoning); -1 only when suppressing. Directive-only clusters are valid.
- [CORE]: `equation.py` — skip brevity check on headings. Short headings (## Format) are organizational, not instructions.
- [CORE]: `equation.py` — fix "0 of N" nonsensical message in overall-strength diagnostic.
- [CORE]: `registry.py` — exclude `_deferred/` directories from rule loading.
- [CORE]: Fix rule match scoping — rules skip entirely when target surface doesn't exist. A rule with `match: {type: config}` won't fire when no config files are present. Mechanical runner, content checker, and violation attribution all gate on surface existence.
- [CLI]: Filter project-level noise ("no matching files") from display. Disambiguate duplicate filenames with parent directory. Fold tests into main group.
- [TESTS]: Update test expectations for 6 renamed rule slugs
- [CORE]: `equation.py` — fix position weight underflow: clamp to non-negative when AMBIGUOUS exclusion shrinks atom count
- [CLI]: `ambiguous_charge` added to aggregate display rules — shows as "N ambiguous" in per-file summaries
- [CORE]: `agents.py` — `_glob_file_type_patterns` resolves external paths (`~/...`, `/absolute/...`) for instruction discovery. Auto-memory (`~/.claude/projects/*/memory/MEMORY.md`), user-level rules, and managed policies are now part of the instruction surface. Project-scoped patterns resolve to the current project only.
- [CORE]: `mapper.py` — map validator accepts AMBIGUOUS charge type and charge_value=0+AMBIGUOUS consistency
- [CORE]: `mapper.py` — `expand_imports()` expands `@path` inline imports before tokenization. Claude Code and Gemini CLI splice imported file content at the reference position — the mapper must see the same expanded content. Resolves relative to importing file, expands `~/`, recurses up to 5 hops, detects circular imports, follows symlinks safely, skips code blocks and non-markdown files.
- [CORE]: `api_client.py` — v2 wire format: obfuscate atom field names (short keys, integer enums, file index references) in API transport. Schema version bumped to `"2"`. IP-revealing semantic names no longer leave the client.
- [CORE]: `api_client.py` — `AilsClient.lint()` sends diagnostics to API instead of returning `None`. Tier gating via `AILS_TIER` env var (default: "free")
- [CORE]: `merger.py` — `CombinedResult` gains `hints` field; `merge_results()` accepts and passes through hints
- [CORE]: `client_checks.py` — all diagnostic messages rewritten to user-facing product language (no theory notation, experiment IDs, or equation constants)
- [CLI]: Show rule IDs on structural and verbose quality findings in text output — each finding line now ends with its rule ID (e.g., `CORE:C:0003`)
- [CLI]: `ails check` text output redesigned — files sorted worst-first, per-file aggregated counts + top actionable findings, hints section, scorecard. Default 5 files, 15 with `-v`
- [FORMATTERS]: JSON output grouped by file with `fix` field, sorted worst-first
- [MCP]: `validate` and `score` tools updated for `LintResult` return type
- [CORE]: `Models.st` property now returns an `OnnxEmbedder` instead of `SentenceTransformer`. Same `.encode(texts)` API, bit-identical output (405 findings exact match with the sentence-transformers baseline, float32 epsilon), no torch in the critical path. The thread-safe lazy load + `_st_lock` structure is unchanged; only the body of the property swapped.
- [BUILD]: `sentence-transformers` removed from all dependency groups. `onnxruntime>=1.18,<2`, `tokenizers>=0.19,<1`, `numpy>=1.26,<3`, `spacy>=3.8.11,<4`, and the `en_core_web_sm` spaCy model wheel moved into `[project].dependencies`. Fresh `uv sync` also uninstalls `torch`, `transformers`, `triton`, and ~15 `nvidia-cuda-*` runtime packages — the installed venv footprint drops by several hundred MB.
- [BUILD]: `[tool.hatch.build.targets.wheel].artifacts` now includes `src/reporails_cli/bundled/models/**/*` so the bundled ONNX files ship in the wheel. `[tool.hatch.metadata].allow-direct-references = true` is required for the `en_core_web_sm` GitHub-release URL pin.
- [CORE]: `Models.warmup()` — parallel preload of spaCy + sentence-transformers via `ThreadPoolExecutor`; thread-safe lazy load with per-model locks on `Models.st` / `Models.nlp`
- [CORE]: `spacy.load("en_core_web_sm")` now loads only `tok2vec + tagger + parser` — classification reads only `tok.dep_`/`tok.tag_`/`tok.text`, so `ner`/`lemmatizer`/`attribute_ruler` are dead weight (verified byte-identical check output)
- [CORE]: Mapper daemon now binds its Unix socket BEFORE model warmup and warms in a background thread; parent's `start_daemon` returns once the socket exists rather than blocking on full model load
- [CORE]: Mapper daemon pre-loads BOTH spaCy and sentence-transformers (was only sentence-transformers); daemon dispatch no longer blocks on warmup, letting cache-hit `map_ruleset` requests return before models are loaded
- [CORE]: Daemon idle timeout raised from 15min to 1h, configurable via `AILS_DAEMON_IDLE_S` env var
- [CORE]: `SentenceTransformer` loaded with explicit `device="cpu"` to skip CUDA probing on GPU-driverless CPU boxes
- [CLI]: `ails check` now eagerly forks the mapper daemon at the top of the command (before file discovery) so model warmup overlaps with the parent's discovery + M-probe work; in-process mapping is the fallback when fork is unavailable
- [RULES]: Dissolve X (context_quality) category — reclassify X:0001-0003→C:0033-0035, X:0004-0005→S:0037-0038, X:0006→E:0006; archive X:0007
- [RULES]: Fix match type on S:0008, S:0010 — use `match: {}` instead of `match: {type: main}` (structure rules apply to all files)
- [RULES]: Downgrade S:0038 (was X:0005), COPILOT:S:0001 checks from deterministic to mechanical (frontmatter_key) — eliminates regex/SARIF overhead
- [RULES]: Add mechanical file_exists gate to S:0012 — skip regex when file missing
- [RULES]: Add mechanical content_absent pre-filters to C:0029, C:0030, G:0002 — short-circuit before deterministic regex
- [RULES]: Extract vocab.yml term lists for 61 rules from existing checks.yml patterns
- [RULES]: Remove stopwords.txt files — replaced by vocab.yml
- [RULES]: Add 30 interaction rules from vertex predictions (agent-neutrality, scope-adherence, cross-file, config-coherence, constraint-propagation)
- [RULES]: Rename 22 rules from verbose slugs to concise names (IDs preserved)
- [REGISTRY]: Remove tier filtering and sources.yml loading from check path — all rules are CORE tier, saves ~170ms

- [LEVELS]: Target existence gating — rules fire when their target file type exists
- [LEVELS]: Project level computed from file type property divergence (format, cardinality, precedence, loading, scope)
- [LEVELS]: Single-pass validation replaces progressive level walk
- [LEVELS]: L0 is now "Absent" (no files); L1 is "Present" (files with baseline properties)
- [RULES]: Strip `level:` field from all rule frontmatter (~90 files) — level is now emergent
- [BOOTSTRAP]: Fix `get_rules_path()` for framework repo structure (rules/ subdirectory)
- [BOOTSTRAP]: Flatten agent path layout (agents/{agent}/ → {agent}/)
- [BOOTSTRAP]: Replace get_agent_vars with get_agent_file_types
- [MECHANICAL]: Rewrite check resolution to use classified file types instead of template vars
- [PIPELINE]: Replace template_vars/instruction_files params with classified_files
- [ENGINE]: Replace `build_template_context` with `build_file_context` (classified file types)
- [ENGINE]: Add mixed-signals multi-agent support — merge file_types from all detected agents
- [ENGINE]: Group rules by resolved target files for batched regex calls
- [HARNESS]: Replace template vars with file_types in agent config loading and test harness
- [HARNESS]: Load checks from checks.yml when rule.md frontmatter has no checks array
- [DISCOVER]: Extract detection data into bundled project-types.yml, data-driven discovery engine
- [CLI]: Extract display helpers, add agent filter resolution, simplify map command
- [META]: Update backbone.yml with new bundled entries and module paths
- [META]: Update backbone.yml — remove external rules dependency, add rules/schemas/registry to modules
- [BOOTSTRAP]: Split config loading into `core/config.py` (get_agent_config, get_global_config, get_project_config); re-export from bootstrap.py
- [BOOTSTRAP]: Simplify `get_rules_path()` resolution: config override → bundled (remove local `./checks/` and installed-mode fallbacks)
- [BOOTSTRAP]: `get_framework_root()` resolves bundled package root for schemas/registry/sources.yml access
- [BOOTSTRAP]: `is_initialized()` recognizes bundled rules — `ails check` works without prior `ails install`
- [BOOTSTRAP]: Remove `FRAMEWORK_REPO` and `FRAMEWORK_RELEASE_URL` constants
- [RULE_BUILDER]: `_load_source_weights()` uses multi-candidate path search for sources.yml (handles bundled layout)
- [RULE_BUILDER]: `get_rule_yml_paths()` renamed to `get_checks_paths()`; `build_rule()` loads checks from `checks.yml` when frontmatter has no `checks:` array
- [REGISTRY]: Pre-parse checks.yml in registry to avoid redundant YAML parsing in build_rule
- [REGISTRY]: Add YAML file cache to eliminate double-parsing between registry and compiler
- [BUILD]: Remove `only-include` constraint — `force-include` injects bundled content into wheel
- [TESTS]: Update `dev_rules_dir` fixture to use in-repo `rules/` instead of sibling `../rules/`
- [TESTS]: Update conftest fixtures and golden snapshots for 0.5.0 rule set
- [TESTS]: Update unit tests for classified file types, add discover test suite
- [TESTS]: Update integration tests for classified file system, remove template resolution tests
- [TESTS]: Update smoke tests for mixed-signals multi-agent behavior
- [TESTS]: Rewrite level and applicability tests for target existence gating
- [TESTS]: Update behavioral and smoke tests for L0 absent level
- [TESTS]: Update golden snapshots and pipeline smoke test for target existence gating
- [TESTS]: Add fail fixtures for 25 rules that had none — harness now at 85 passed, 0 failed, 4 no_fixtures
- [TESTS]: Fix copilot applyto-scope-declared fixtures (`.claude/rules/` → `.github/instructions/`), add frontmatter to path-scope-declared pass fixture
- [TESTS]: Update Check/Rule constructors and YAML fixtures for checks consolidation and severity lift
- [CLI]: `ails check` — new pipeline (discover → M probes → map → client checks → server → merge → display)
- [CLI]: `ails check` — add spinner progress phases, suppress ML library stderr noise
- [MCP]: `validate` and `score` tools use new pipeline returning `CombinedResult`
- [FORMATTERS]: Add `format_combined_result()` to JSON and GitHub formatters
- [REGEX]: Add `run_checks()` returning `list[LocalFinding]` alongside SARIF `run_validation()`
- [CLI]: Fixing deploy.
- [META]: Fix 50 mypy strict-mode errors across `core/` and `cli/main.py` — type annotations, unused ignores, untyped lambdas
- [META]: Fix ruff lint errors in `tests/unit/test_api_client.py` — unused import, dict literal
- [META]: Exclude `_archived/` from mypy in `pyproject.toml`
- [ACTION]: Remove invalid `--no-update-check` flag from `action/action.yml`
- [TESTS]: Remove stale integration tests for removed features (update, dismiss, judge, --no-update-check, -q, --refresh, --legend, compact/brief formats)
- [TESTS]: Add `requires_model` skip marker for integration tests needing bundled ONNX model
- [TESTS]: Fix MCP test expectations for current tool set (heal replaces judge)
- [CORE]: Gracefully handle missing ONNX model — catch `RuntimeError` alongside `ImportError` in mapper fallback paths (check, heal, MCP tools)
- [TESTS]: Update integration tests for `CombinedResult` JSON schema (`files`/`stats` replaces `score`/`level`/`violations`)
- [TESTS]: Rewrite `test_summary.py` for `CombinedResult` schema
- [ACTION]: Add `parse_result.py` — compute score, level, violations from `CombinedResult` JSON
- [CLI]: `--strict` exits 1 on any finding, not just errors
- [BUILD]: Remove `en-core-web-sm` direct URL dependency (rejected by PyPI). spaCy model auto-downloads on first run if missing.
- [CLI]: `ails version` shows only CLI version and install method — remove stale Framework/Recommended lines
- [BUILD]: Add `scikit-learn` to runtime dependencies — required by mapper topic clustering
- [TESTS]: Fix remaining MCP and CLI integration tests for `CombinedResult` schema — remove `score`/`level` assertions, use `files`/`stats`

### Fixed

- [SCORER]: Return 0.0 instead of 10.0 when no rules checked (L0) — no data is not perfection
- [FORMATTERS]: Suppress score display at L0 — show level-only message instead of misleading 10.0/10
- [FORMATTERS]: Fix violation message word-break truncation using wrong baseline for space search

- [MECHANICAL]: Fix `file_absent` false positives when match_type is set but no files of that type are classified
- [REGEX]: Add signal-based timeout (500ms) to guard against catastrophic backtracking in regex patterns
- [MECHANICAL]: `resolve_location` returns paths relative to scan root instead of bare filenames — fixes scoped-rule violation locations
- [BOOTSTRAP]: `get_rules_path()` returns correct subdirectory in framework dev mode
- [BOOTSTRAP]: `get_schemas_path()` uses framework root, not rules path
- [ENGINE]: Remove `**/*` fallback in `_get_counted_files` — no longer globs entire project tree

### Docs

- [README]: Rules are bundled — remove external rules repo references and separate install instructions

### Removed

- [REGISTRY]: Delete coordinate-map.yml, tombstones.yml, capabilities.yml — no source code consumers
- [CLI]: Remove `--experimental` flag from `check` and `heal` commands — always-false, dead since tier consolidation
- [MODELS]: Remove `Rule.level` field — level is emergent from file type properties, not stored per-rule
- [MODELS]: Remove `SkippedExperimental` class and `ProjectConfig.experimental` field
- [ENGINE]: Remove `include_experimental` parameter from `run_validation` and `run_validation_sync`
- [CLASSIFICATION]: Add `detect_content_format()` — auto-detect prose/heading/code_block/data_block/table/list in freeform files
- [CLASSIFICATION]: Add `content_format` to `_file_matches()` property loop — rules can now target specific content regions
- [REGISTRY]: Remove `get_experimental_rules()` deprecated stub
- [ENGINE]: Delete template variable resolution system (templates.py)
- [REGEX]: Remove template_context parameter from compile/run
- [ENGINE]: Remove two-phase capability detection pipeline (_detect_capabilities, ContentFeatures, CapabilityResult)
- [BUNDLED]: Delete capability-patterns.yml — no longer needed for level determination
- [REGEX]: Remove run_capability_detection function — capabilities not detected via regex
- [LEVELS]: Remove legacy level determination functions — level is now emergent from file type properties
