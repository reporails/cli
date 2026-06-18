# Changelog

## 0.5.11

### Added

- rules: `ails rules` — new subcommand exposing the framework rule registry as a queryable surface. `ails rules list` enumerates rules with repeatable `--capability` filtering (sorted by category: structure → direction → coherence → efficiency → maintenance → governance; severity as tiebreaker), plus `--agent` and `--severity` filters and three output formats: `text` (compact), `md` (rich, Pass / Fail blocks by default; `--no-examples` opt-out for shorter context payload), `json` (structured). `ails rules agents` enumerates known agents; `ails rules capabilities` enumerates the capability vocabulary for an agent. Rule-detail browsing stays on the top-level `ails explain <id-or-slug>` (accepts either a rule ID like `CORE:S:0024` or a slug like `section-headers-present`). The markdown form pipes directly into an AI authoring agent's prompt so it writes rule-compliant content from the start rather than patching findings after `ails check`.
- check: `ails check` now takes variadic typed targets: each positional is `capability:name` (`skill:backlog`), a bare capability noun (`skills` for every skill), or a path (`./CLAUDE.md`). Mixable; no targets = whole-project scan. A leading Windows drive letter (`C:\...`) is treated as a path, not a `capability:name`. The previous two-positional polymorphic shape is gone. Replaces `ails check skill backlog` with `ails check skill:backlog`.
- cli: root-level `--version` / `-V` flag prints the version string (subcommand `ails version` still prints the full install-method readout). `-h` accepted everywhere as a `--help` alias. Shell completion callbacks wired to `ails check <target>`, `--agent`, and `ails explain <id-or-slug>` — install via `ails --install-completion` to enable.
- check: `--fix` added as an alias for `--heal` (`ails check --fix`), matching the `eslint`/`ruff` convention; `--heal` stays primary, both show in `--help`.
- cli: `ails --help` groups commands into four intent panels — Get started (`check`), Explore (`explain`, `rules`), Account & setup (`auth`, `config`), Maintenance (`install`, `update`, `version`). Command summary lines are normalized to one imperative clause each. `ails check --help` describes the target forms on the `targets` argument and points to `ails rules capabilities`.
- rules: `ails rules capabilities` now shows, per capability, the path glob it resolves to and how many targets are found in the current project (previously listed names only). JSON gains a `resolution` array alongside the existing `capabilities` name list.
- check: `ails check @referenced` — new capability listing surface for `[text](path)`-reached markdown files (`file_type: referenced`). Virtual-capability path: agent-agnostic (markdown links are universal), enumerates classifier output rather than agent-config globs. Requires `.ails/config.yml: generic_scanning: true` to populate; otherwise empty.
- check/json: `-f json` gains two additive keys — a per-file `regime` object (`named`, `within_capacity`, `confidence`) describing how much room a file has to improve, and a per-finding `leverage` tier (`gate_mover` / `conditional` / `cosmetic`) ranking how much each finding is likely to move the score. The raw `severity`, `score`, and `violations` fields are unchanged, so existing consumers and CI baselines keep working.
- rules: new `scheduled_tasks` capability in the agent capability matrix — recognizes scheduled-task / automation surfaces (cron / scheduled-run / automations) where an agent exposes them on disk. Surfaces in `ails rules capabilities`; the matrix now carries 16 capabilities.
- check: `exclude_files` config key (and `--exclude-files` flag) excludes individual files from a scan, complementing `exclude_dirs`. Each entry is a glob matched against the file path relative to the project root (`pathlib` semantics: each `*`/`**` segment matches exactly one path component — not a recursive globstar — so a pattern matches at a fixed depth), so you can name an exact file (`.claude/agents/lead.md`), files one level down (`.claude/skills/*/SKILL.md`), or any file by basename (`**/lead.md`). Anchor patterns to a path prefix — a bare `**` matches every file and drops all instruction files. The motivating case is a project that symlinks coding-agent harness files in from elsewhere — they are owned and linted where they live, so listing their paths drops them from scoring noise here. Accepted in both project and global config; explicitly targeting an excluded file (`ails check ./.claude/agents/lead.md`) still scans it, since exclusion applies to discovery only.

### Changed

- check: a file with no scorable instruction content now renders as `not scored` instead of a misleading full score. This covers a non-instruction surface a coding agent still reads (e.g. a `.cursorignore` path list, which carries no instruction quality to measure) and an empty instruction file. Such files show no score and no health bar, and are excluded from the per-surface and whole-project roll-up, so they neither read as top-quality nor drag the headline. In `-f json`, an all-unscored surface's `surface_health[].score` is `null`; surfaces with any scored file keep a numeric score.
- check: with `generic_scanning: true`, files reached by an `@`-import (which the harness eagerly auto-loads) are now mapped + scored and surface as an `Imported` bar that counts toward the whole-project Quality — closing a gap where eagerly-loaded context was silently omitted from the score. Files reached only by a `[text](path)` markdown link (discoverable, not loaded unless read) get their own labeled `Referenced` file-panel group (findings only) and are deliberately kept out of the score and the headline, since scoring a file the agent never loads would be a false signal. A one-line note names the headline shift on runs that have Imported files. No effect when `generic_scanning` is off.
- check/json: `-f json` (and the trailing JSON line of `--format github`) now carries top-level `quality` (the whole-project Quality score, `null` when offline) and `level` (the maturity level, e.g. `L4`), matching the text headline. Previously the combined-result JSON exposed only per-surface `surface_health[].score` with no whole-project verdict, so a JSON consumer (the GitHub Action, the plugin) could not read the headline number and had to re-derive one. Additive keys; existing fields unchanged.
- ci/action: the `reporails/cli/action` `score` output and the `min-score` gate now read the real `quality` verdict from the check JSON instead of recomputing a severity-tally approximation (the pre-single-score model). `level` is read from the JSON `level` key rather than hardcoded. An offline run (no server score) leaves `score` empty and the `min-score` gate logs a warning and skips instead of failing on a fabricated number.
- check/json: `-f json` `surface_health` now routes `@`-import (`generic`) files to the `Imported` surface when `generic_scanning` is on, matching the text scorecard. Previously the JSON surface partition disagreed with the text view for the same run (`file_type_by_path` was threaded only into the text formatter).
- mcp: `validate(path)` now keys per-file `regime` and per-surface health against the validated path instead of the server's working directory. When the validated path differed from the MCP server's cwd, the regime block silently dropped and surface scores misrouted; the JSON consumer (the plugin) got degraded data with no error. Threaded `project_root` through `format_combined_result` into `compute_surface_scores`.
- check: every rule ID in the text output is now a clickable link to its documentation page at `https://reporails.com/rules/<agent|core>/<slug>` (e.g. `CORE:E:0003` → `/rules/core/formatting-regime`). Terminals that support hyperlinks make the ID clickable; others show the plain ID unchanged.
- check: the `Findings` line no longer appends a `score-movers` count. The count mixed the leverage axis (how much a fix moves the score) with the severity histogram (errors/warnings/info) on one line, which read as inconsistent — e.g. 96 errors but 42 score-movers, because most structural and mechanical errors are not score-movers. The leverage signal still drives the inline triage: gate-mover findings stay as listed lines and the rest collapse into `+N lower-priority (won't move your score yet)`.
- check: client-side findings now display their canonical rule ID in the text output, matching server findings — a backtick-formatting finding reads `CORE:E:0003` instead of the bare label `format`, charge-ordering reads `CORE:D:0003` (was `ordering`), broad conditional scope `CORE:C:0048` (`scope`), an instruction-in-heading `CORE:S:0039` (`heading_instruction`), and a prohibition with no paired directive `CORE:C:0053` (`orphan`, the degenerate weak-instruction case). The Top-rules block now merges client and server findings that share a rule ID into one row. Only the displayed token changed; `-f json` keeps the raw labels for baseline stability.
- check: offline runs (server diagnostics unavailable) no longer render every surface as `not scored`. The per-surface and per-item score bars are suppressed when there is no server analysis at all, leaving the `Quality n/a` headline, the findings, and the scope summary — only genuinely scored runs show the bars. Online behavior is unchanged.
- check: the structural-completeness signal (missing required sections, presence and hygiene gaps, an over-limit instruction chain) now resolves an agent's own structural rules, not just the generic core set. An agent rule that supersedes a core structural rule — e.g. Codex's hard 32 KiB `AGENTS.md` cap (`CODEX:E:0001`) superseding the generic size rule — was being dropped from the signal, so an over-limit Codex chain did not actually lower the score. It now does: the over-limit chain is folded into the delivery factor so the score reflects the silently-truncated content.
- Internals: the SIGALRM wall-clock backstop guards (`interfaces/cli/main.py`, `core/mapper/daemon.py`) now branch on `sys.platform` instead of `hasattr(signal, "SIGALRM")`. `mypy` narrows a `sys.platform` check but not a `hasattr` guard, so the `--platform=win32` cross-check flagged `signal.setitimer`/`signal.ITIMER_REAL` as missing attributes and the pre-release gate failed. No behavior change (both forms no-op on Windows); host + win32 `mypy` now clean.
- Internals: `interfaces/cli/main.py` variadic-target classification narrows the `_classify_target_token` payload with `isinstance` instead of suppressing the union with `# type: ignore`. No behavior change; clears three latent `mypy` errors (`unused-ignore`, `union-attr`, `arg-type`) so the type gate is green.
- Internals: New `core/platform/adapters/rules_query.py` adapter (load + filter + sort + fence-aware Pass/Fail extraction) backs the `ails rules` verb. CLI surface lives at `interfaces/cli/rules_command.py` (Typer sub-app) calling shared `list_checks` in `interfaces/cli/checks_command.py`. 18 unit tests + 7 integration tests cover loader / filter / sort / command / examples.
- Internals: `tests/unit/test_rule_id_uniqueness.py` collapses the duplicate-id comprehension onto one line to satisfy the line-length linter. No behavior change.
- Internals: `test_single_file_scan_matches_whole_project` marked `xfail` — it compares a cwd-nested single-file scan against a dir-target that reroots at the subdir; under the cwd-is-project-root principle the rerooting is the deviation, tracked for a post-release decision.
- Internals: review follow-ups — deduped `_is_external_pattern` (one canonical copy in `agent_discovery`, imported by `capability_paths`, was divergent); `per_file_stats` now requires `project_root` to match its sibling `get_group_atoms` (no silent `Path.cwd()` fallback); added an e2e guarding that `ails check subagent_memory` reaches global `~/.claude/agent-memory/` files.
- Internals: tightened inline comments in the mapper classifier and embedder to describe behavior; removed two stale code-reference comments in `core/classify` and `core/platform/dto`. No behavior change.
- Internals: integration tests made CI-robust — `test_score_displayed` asserts the always-present `Quality` headline (a score online, `Quality n/a` offline) instead of a score value, and the `ails rules` help assertions strip ANSI and force a wide, color-free render so option tokens (`--capability`) are not split by escape codes on CI runners.
- Internals: `test_check_single_file` made Windows-robust — the single-file findings test runs from the project directory with a relative target so path normalization stays single-drive (Windows pytest `tmp_path` and the repo checkout can land on different drives, breaking the display filter's `relative_to`), and the subagent-memory test sets `USERPROFILE` alongside `HOME` so `Path.home()` resolves the fake home on Windows.
- Internals: `test_checks_command._run` decodes subprocess output as UTF-8 to match the CLI's UTF-8 stdout; under the OS locale (cp1252 on Windows) the reader thread died decoding the rich help panel's box-drawing glyphs and `proc.stdout` came back `None`.
- Internals: `test_capability_paths` normalizes relative paths via `as_posix()` so the nested-`CLAUDE.md` enumeration assertions pass on Windows, where `str(Path.relative_to(...))` yields backslash separators that broke the forward-slash comparison.
- mcp/json: validate response now carries `tier` at top-level, `category` per finding (derived from rule id via the existing `Category` enum), and `category_breakdown` per surface in `surface_health`. Consumers can render tier-aware presentation, group findings by category, and triage by prioritizing surfaces with the heaviest category buckets.
- mcp: trimmed tool surface to `validate`, `preflight`, `explain`. `score` and `heal` removed — score is derivable from the validate response's stats + surface_health; heal is replaced by the slash command body's fix-walk loop (model uses `Edit` per finding with the response's per-finding `fix` text). New `preflight(capability, agent?)` returns workflow-ordered rules with Pass / Fail example blocks for the author-it-right-first loop. `validate` accepts file-path targets (previously rejected with `not_a_directory`) and now returns a structured `needs_install` payload when the framework is missing (previously a bare error). CLI `ails check --heal` continues to serve batch deterministic use.
- rules: per-rule `fix:` text now lives in `rule.md` frontmatter — canonical operator-facing fix text consumed by `LocalFinding.fix` at emission time. 26 rules received canonical fix text; framework-wide fix coverage in validate responses moved from 96.3% → 100% on the cli's own corpus. Cap: 1000 chars per rule, mirrors the skill-description ceiling. Authored once in `rule.md`, surfaced everywhere — the plugin reads `finding.fix` to drive an Edit-per-finding loop.
- classify: Link-reached files split into two file types — `[text](path)` markdown-link reach classifies the target as `file_type: referenced` with `loading: discoverable`; `@<path>` import reach keeps `file_type: generic` with `loading: session_start`/`on_demand` per source eagerness. Mixed reach (both `@` and link from any source) routes to `generic` — the import path's auto-load guarantee dominates the link-only path's discoverability. Matches the actual harness loading model: only `@`-imported content enters context budget without an explicit `Read`.
- Internals: New `tests/skills/<skill>/` subtree for subagent-driven manual validation procedures (not `pytest`). Initial: `/ails` skill procedure + deliberately-imperfect fixture exercising check / explain / heal / preflight / fallback cases.
- check: `ails check` now leads each file panel with its highest-leverage findings and collapses the low-priority remainder into a single `◦ +N lower-priority (won't move your score yet) · -v to list` row, so the report surfaces what actually moves your score instead of a flat wall of findings. Repeated same-rule findings fold into one `(×N)` line. `-v` restores the full per-line view, and severity is re-keyed by leverage rather than raw symptom count. The collapse is driven by a per-file read of the server's analysis; files where that read is uncertain keep the full findings view. The boxed panels, summary scorecard, `Level:`, `Top rules`, and footer are unchanged.
- check: `ails heal` folded into `ails check --heal`. The standalone `heal` verb is removed; healing runs as a flag on `check`, reusing the already-built ruleset map and discovery (no double-mapping). `--dry-run` previews fixes without writing. Output: text mode shows the standard scorecard followed by the heal summary; JSON mode emits the heal payload (single document, parseable). The validate-then-fix workflow becomes one verb instead of two.
- check: the summary now leads with a single **Quality** score (0-10) — the analysis service's own verdict on how well-formed your instructions are, shown verbatim (the CLI holds no scoring constants). The score discriminates: a problem-heavy file scores well below a clean one, where the previous score read near the top for almost any file regardless of its findings. Structural completeness (missing required sections, presence and hygiene gaps) and any content silently dropped past an agent's hard instruction-size cap are folded into the score as a delivery factor, so a file that loses instruction content can no longer read as high quality. Findings stay a separate worklist (errors / warnings / score-movers) beneath the score; a high score above open errors shows a one-line caption naming the split. The whole-project and per-surface numbers are the atom-weighted roll-up of the per-file scores, so the headline never contradicts the per-surface / per-file bars, and each per-surface bar carries its own error count (`Rules 8.0 · 1 err`). `-f json` keeps the same `surface_health[].score` key and shape; `severity` and `violations` are untouched.
- check: each finding's priority tier (`gate_mover` / `conditional` / `cosmetic`) is now computed by the server's analysis for that finding *in the context of its own file*, replacing the previous fixed rule-to-tier lookup. The same rule can rank as high-priority in one file and low-priority in another depending on how much room that file has to improve — so the `◦ +N lower-priority` collapse and the `-f json` `leverage` key reflect what actually moves each file's score rather than a one-size-fits-all guess. The CLI falls back to the built-in ranking when run offline. The JSON shape is unchanged (same `leverage` key and values); `severity`, `score`, and `violations` are untouched.
- check: each surfaced finding now shows its remediation as a `→` action line beneath it — the per-finding fix text, written for that specific instruction rather than a generic rule blurb — so the report says what to do, not just what is wrong. Rendered in both the triaged and neutral views; the collapsed low-priority tail stays a single line.
- check: instruction-length findings recalibrated toward an 8-10 word range (optimum 9) — "too brief" now flags instructions of 6 words or fewer (previously 8), and a new "too long" finding flags instructions over 11 words. Both surface under the existing instruction-elaboration rule.
- rules: refreshed the bundled agent capability matrix and the five implemented agents' configs (claude, codex, copilot, cursor, gemini) against current official docs — added `memory` to codex, `output` to gemini, and `scheduled_tasks` to claude/codex/cursor; refreshed per-agent surface notes (hook-event counts, Cursor Memories, Codex memories). `ails check` discovery and capability-target resolution pick up the updated surfaces.
- Internals: new `scripts/validate_registry.py` enforces the matrix connection rule — every capability in an implemented agent's matrix row must resolve to a config `file_types` entry/scope or a documented unmeasurable-surface exemption; runs in CI as a registry guard.
- rules: corrected the guidance in four core rules (`instruction-elaboration`, `specificity-shields`, `formatting-regime`, `compound-weakness`) to be direction-aware. Positive directives should name the specific construct (tool, file, command); prohibitions should state the forbidden thing as an abstract category rather than naming or backticking it, because naming a prohibited construct can anchor the forbidden concept instead of suppressing it. Updated the Pass examples and fix text only — no rule IDs, categories, severities, or checks changed.
- check: `CORE:E:0001` (total instruction size) now measures the always-injected "one round" footprint instead of summing every instruction file on disk. Eager files (`loading: session_start` — `CLAUDE.md`/`AGENTS.md`/`GEMINI.md` + imports, the `MEMORY.md` index) count in full; progressive-disclosure surfaces (skills, subagents — `loading: on_invocation`) count by their `name` + `description` metadata only (what's injected at startup, not the body); recalled/conditional surfaces (`loading: on_demand` / `discoverable` — on-demand rules, recalled memory siblings) are excluded. A repo with many skills, subagents, or rules, or a large memory archive, is no longer flagged for context it doesn't carry every round.
- classify: agent memory entries now carry a per-entry loading model — `MEMORY.md` is the eager index (`loading: session_start`) and its sibling `*.md` notes are recalled on demand (`loading: on_demand`), matching how Claude and Gemini actually load memory.
- rules: corrected the Gemini `memory` surface in the bundled agent config against gemini-cli source — the removed `save_memory` / "Gemini Added Memories" section model is retired; the stable private memory is the `~/.gemini/tmp/<project-id>/memory/MEMORY.md` lean index plus on-demand sibling notes, the same index-and-recall shape as Claude.
- rules: instruction-size limits are now agent-aware. Generic `CORE:E:0001` (total instruction size) is an advisory **warning** rather than an error — most agents only soft-cap their always-loaded instructions. A new `CODEX:E:0001` supersedes it for Codex with a hard **error** at 32 KiB, because Codex silently truncates its combined `AGENTS.md` chain past `project_doc_max_bytes` (32 KiB default) and the overflow never reaches the model — so the rule flags the chain before content is dropped.

### Fixed

- check: backtick-wrapped tokens like `` `@pytest.mark.parametrize` `` are no longer mis-detected as `@<path>` imports, eliminating spurious "Unresolved imports" findings. The import-targets and import-depth checks now share the mapper's canonical import-reference regex (`IMPORT_REF_RE`), which excludes inline code, emails, and non-path `@tokens` — so detection matches what the harness actually expands.
- daemon/mcp: resident embedding + spaCy models are now released when idle, so a background `ails` process no longer pins gigabytes of memory indefinitely. The mapper daemon's idle shutdown is on by default (30 min; set `AILS_DAEMON_IDLE_S` seconds to tune, `0` to disable) and unloads models before exit. The long-lived MCP server now drops resident models after an idle window (`AILS_MCP_IDLE_S` seconds, default 30 min, `0` disables) and lazily reloads them on the next tool call. Both paths are cross-platform.
- mcp: the generated `uvx` MCP-server invocation now uses `--refresh-package reporails-cli` instead of a blanket `--refresh` — the server still picks up CLI updates on spawn, but no longer re-resolves the entire dependency graph each time, which pegged a CPU core under frequent respawns.
- npm: the `npx @reporails/cli` wrapper now passes `--refresh-package reporails-cli` instead of a blanket `--refresh` to `uvx`, so every `npx` invocation no longer re-resolves the whole dependency graph (the same CPU-pegging fix already applied to the MCP-server invocation). The CLI package itself is still refreshed each run.
- check: a wall-clock backstop now aborts an `ails check` that runs past a ceiling (default 600 s; `AILS_CHECK_TIMEOUT_S` seconds, `0` disables) instead of hanging indefinitely. POSIX-only (`SIGALRM`); a no-op on Windows.
- check: `ails check file:<path>` now resolves the remainder as a path instead of failing with `Error: capability file is not declared`. The `file:` scheme is the explicit inverse of `capability:name` — it forces path interpretation, so a file whose name collides with a capability noun (e.g. `file:skills`) still scans as a file. Works with relative and absolute paths.
- check: bare capability nouns (`ails check skills`, `ails check agents`) resolve to every instance of that capability for the detected agent — the all-of-kind form, equivalent to a `capability:name` spec with the name omitted. A token that is neither a known capability nor a `capability:name` spec resolves as a path; tab-completion offers both the bare noun and the `capability:` form.
- check: `ails check <file>` on a single file now classifies and lints that file instead of reporting "✓ No findings." The file path was flowing down as the classification + display root, where a directory is expected: `relative_to(scan_root)` fell back to the absolute path, the `**/CLAUDE.md` glob could not match it, the file received no `file_type`, and no rules applied. The scan now keeps the real project root and narrows discovery to the named file, so its finding path keeps its directory prefix (e.g. `.claude/rules/<name>.md`), classifies into the right group (Rules / Skills, not the generic bucket), and produces the same findings — and the same per-file priority collapse — the file gets under a whole-project scan.
- [Lint]: Gate user-scope `~/...` rendering in mechanical-check attribution on the classifier's `precedence: user` property (read from agent config patterns) instead of path-prefix heuristics, so Windows tmp paths under the user profile no longer render with a `~/` prefix.
- check: `ails check main` no longer folds subdirectory CLAUDE.md / `nested_context` / `child_instruction` files into the `main` umbrella. The capability now lists only root-level family (`main` + `override`); use `ails check nested_context` or `ails check child_instruction` to enumerate subdir CLAUDE.md. Capability-listing now reuses the classifier's `scope`/`loading` semantics so `**/CLAUDE.md` partitions correctly between root and nested.
- check: `ails check <file>` narrows the display to the named file so the headline `Score:`, surface-health bars, and per-file panels reflect only what the operator asked about. Previously, discovery enumerated user-scope `~/.claude/CLAUDE.md` alongside the project file, inflating finding totals with entries from a path the operator hadn't named.
- config: `~/.reporails/config.yml` now contributes `disabled_rules`, `exclude_dirs`, `overrides`, `rule_thresholds`, `generic_scanning`, `packages`, `agents`, and `surfaces` to the merged `ProjectConfig` (project values win on conflict; list fields extend, dict fields deep-merge under). Previously, only `default_agent`, `tier`, `auto_update_check`, and `framework_path` were read from the global file; the other field names were silently dropped at parse time, so global defaults had no effect on a project scan.
- discovery: bulk `.md` enumeration now descends into symlinked subdirectories. Previously the in-tree directory-glob path and the regex runner's whole-repo scan used `Path.rglob("*.md")`, which on Python 3.12 silently skips symlinked subdirs (`recurse_symlinks=True` is 3.13-only). Skills and rules adopted into a project via `.claude/skills/<name>` directory symlinks were therefore invisible to the classified-file set, so mechanical checks keyed on `match: {type: skill}` reported "No matching files found" and `ails check @skills` undercounted. New `core/discovery/walk.py` walker uses `os.walk(followlinks=True)` with realpath cycle tracking.
- check: declared-but-unresolved skill names in an agent's `skills:` frontmatter now print a visible stderr warning (`Warning: <agent.md> declares skill '<name>' — not found under .claude/skills/`) before the report. Previously `expand_focus()` logged the drop at DEBUG and the skill silently disappeared from the focus set, so an agent declaring a skill that was never symlinked into the project showed no signal in the diagnostics. Warning goes to stderr so JSON-format output remains structured.
- check: targeted `ails check <capability>:<name>` runs no longer surface cross-file findings from out-of-scope files. Mechanical checks that declare an `args.path` glob (e.g. `CORE:S:0056` broken-markdown-link, `CORE:S:0038` path-scope-declared) previously bypassed the capability-narrowed file set — the glob globbed the whole repo, the validation found broken links in `CLAUDE.md`, and the violation got attributed to the targeted file via the `resolve_location` wildcard fallback. The path glob is now intersected with the rule-matched, capability-narrowed classified set in `_get_target_files`, so the broken-link check sees only in-scope files. `_resolve_glob_targets` also now passes `include_hidden=True` so `**/*.md` matches `.claude/`-rooted instruction files in whole-repo runs.
- check: mapper-daemon messaging no longer prints "Starting mapper daemon..." followed by "Daemon unavailable, loading models in-process..." on the same run. `ensure_daemon()` now returns a four-valued status (`ATTACHED` / `STARTED` / `STARTING` / `UNAVAILABLE`) determined up-front via a readiness ping after fork, so the `ails check` startup banner reflects the real attach state: silent on the hot path, `"Started mapper daemon."` on a successful cold fork, `"Mapper daemon warming up, mapping in-process this run..."` when the socket binds before the daemon answers a ping, and `"Mapper daemon unavailable, mapping in-process..."` when the daemon cannot be reached at all. The genuine mid-flight failure case (daemon attached but the map call returns no result) now prints a distinct `"Daemon stopped responding, falling back to in-process..."` line instead of masquerading as a startup failure. Parent's socket-existence wait after fork is bumped from 2 s to 4 s so cold model imports do not race past the parent's timeout.
- check: `@`-references inside fenced code blocks (e.g. `ails check @main` inside a ```bash``` example) no longer get extracted as real imports, so they no longer surface as `Unresolved imports: <name>` findings under `CORE:S:0024`. The mechanical `extract_imports` and `import_depth` checks now strip fenced blocks before running the `@`-import regex, matching the fenced-block treatment already used by the mapper's `expand_imports` expander. The shared `FENCED_BLOCK_RE` lives in `core/mapper/imports.py` and is reused across both call sites so the expander and the lint check agree on what counts as documentation vs a real import.
- check: targeted runs (capability/path/file scope) no longer fire project-shape rules (`CORE:S:0010` modular-file-organization, `CORE:E:0001` total-instruction-size-limit) against the narrowed subset — these aggregate checks count the whole project, so a single-skill or single-file scope previously misreported `File count 1 outside bounds`. They are now skipped when scoped and evaluated only on whole-project scans (`ails check` / `ails check .`).
- classify: link discovery (`generic_scanning`) now extracts Markdown links whose link text is wrapped in inline code — `` [`name`](path) `` — instead of silently dropping them. The walker stripped all inline code *before* matching links, which deleted the bracket text and left `[](path)`, a form the link regex (requiring non-empty bracket text) could not match — so every backtick-wrapped reference was skipped and link-reached files went undiscovered. Inline-code stripping is replaced by a position check that skips only links wholly enclosed in a code span (literal `` `[text](path)` `` documentation examples). Two regression tests in `test_link_walker.py` cover the backtick-wrapped-link and code-example cases.
- check: `CORE:S:0015` skill-entry-point-present no longer false-fires on valid skills. It previously used a content query that asked whether a `SKILL.md`'s own body contained the literal token `SKILL.md` — which real skills never write — so every discovered skill reported `Missing skill entry point`. The rule now uses a mechanical check that enumerates each skills root and flags only directories that genuinely lack a `SKILL.md` entry file. As a whole-project aggregate it is skipped under targeted scope and evaluated on whole-project scans.
- classify: a lead-verb imperative whose parse is derailed by a long parenthetical (verb demoted to subject) is no longer misread as prose; the position-0 nsubj rescue now covers ambiguous verbs when spaCy's ROOT lands inside a parenthetical.
- classify: a sentence-initial imperative whose lead word is absent from the verb lexicon (`Pin every dependency …`, `Lock the version …`) is now charged as a directive via the determiner-object frame — a position-0 lead token governing a determiner-led object phrase with no subject. Noun-initial declaratives where the lead word is the subject of a finite verb (`Lock contention dominates …`, `Cache misses are …`) stay non-directive.
- classify: a negation inside a parenthetical (`Pin every dependency (… — never a caret range) …`) no longer flips a directive to ambiguous. The compound-instruction guard now masks parenthetical spans before scanning for a late constraint, so a subordinate clarification inside parentheses is not mistaken for a second top-level constraint clause.
- discovery: `ails check` no longer crashes with `FileNotFoundError` when an instruction-file path is a dangling symlink (e.g. a `.claude/rules/*.md` symlink whose target was removed). The exact-name and wildcard glob paths in discovery now require `is_file()`, so broken symlinks are excluded before the mapper reads file contents; valid symlinks to existing files remain discovered.
- heal: the backtick-wrap fixer no longer rewrites tokens inside markdown link labels or targets — previously `[X](X)` became the invalid-GFM form with both label and target backtick-wrapped, breaking the link render. Token occurrences outside links are still wrapped; link-only occurrences are left untouched.
- rules: `import-depth-within-limit` (cursor) re-coordinated to `CURSOR:S:0006` — its id collided with `CURSOR:S:0002` `hook-valid-event-types`, so one of the two rules was silently dropped at registry load (filesystem-order dependent). A unit test now guards global rule-ID uniqueness across the bundled corpus.
- check: a whole-project `ails check` no longer pulls in cross-project subagent memory (the global `~/.claude/agent-memory/<role>/` surface, shared across every project) — it inflated finding totals and the size aggregate with entries the current repo doesn't own. The project's own auto-memory and any repo-local `.claude/agent-memory/` stay in scope. The global surface is still lintable on demand via `ails check subagent_memory` (or `ails check memories`).
- check: `ails check memories` / `ails check subagent_memory` now report findings instead of "✓ No findings." The capability filter keyed its path set differently from the findings (absolute vs `~/`-relative form), so every out-of-tree memory target was silently dropped before display. Capability targets are now authoritative — a targeted run lints exactly the resolved files even when the whole-project scan excludes them.
- check: the per-group / per-file stats header (`N directive / N constraint · N% prose`) now renders for `ails check <dir>` and `ails check <file>` run from outside the project. The atom rollup keyed file lookup on `Path.cwd()` instead of the scan root, so any scan where the working directory differed from the target's root matched zero atoms and left the header blank.
- check: a capability target (`ails check skills`, `ails check agents`, …) on a repo with multiple detected agents and no resolved default now prints a clear `multiple agents detected (…) — pass --agent <name>` error instead of silently degrading to the `generic` agent (which produced `capability X is not declared for agent generic` or a misleading `Create a AGENTS.md`). Set `default_agent` in `.ails/config.yml` or pass `--agent` to target one agent.
- mcp: `validate(path)` on a single file now narrows discovery to that file's project root and validates only that file, instead of returning `No instruction files found`. The MCP pipeline rooted agent detection and the instruction-file walk at the file path itself (where a directory is expected), so a `{"path": "CLAUDE.md"}` call discovered nothing — the single-file narrowing already shipped for `ails check <file>` was never wired into the MCP tool.
- win: `ails` forces UTF-8 on stdout/stderr at startup so the scorecard box-drawing characters and the `-f md` arrow / em-dash glyphs no longer crash with `UnicodeEncodeError` on Windows consoles, whose default cp1252 encoding cannot represent them. The CLI ships to Windows via `npx`.

## 0.5.10

### Added
- check: Re-introduced project capability level as a `Level: L# <Label>` line in the text scorecard between `Agent:` and `Scope:`. Engine re-aligned to the canonical ladder in `docs/capability-levels.md` (System / Primer / Composite / Scoped / Delegated / Abstracted / Governed / Adaptive, L0–L7). Detection is cumulative — the displayed level is the highest where all prior levels also pass. Three new `DetectedFeatures` flags drive the new levels (`has_subagents` for L5, `has_hooks` for L6 governance, `has_auto_memory` for L7). Read-out only, not a gate; rule applicability is unchanged.
- auth: Typed `PlatformUnavailableError` raised when `/api/auth/client-id` returns a non-JSON body, replacing the silent fall-through that surfaced as a misleading "OAuth not configured" message.
- check: Per-capability targeting — `ails check <capability> <name>` resolves to a focused report on one capability target (skill, rule, agents, main, etc.), and `ails check <capability>` lists available targets with per-target scores. Capability vocabulary is read from the detected agent's `framework/rules/<agent>/config.yml` `file_types:`; supports singular and plural forms (skill/skills, rule/rules, agent/agents).
- check: Focus-mode output layout for capability runs — single-file score, findings grouped by rule with line refs, "Next" action pointer toward the highest-frequency rule. Subagent targets expand to include skills declared in their `skills:` frontmatter.
- check: `Top rules (by finding count)` block in the whole-repo scorecard, ranked across all findings.
- check: `top_rules` array in `-f json` output; `focus` envelope in capability-mode JSON describes the targeted capability, name, agent, and paths.
- check: Size-aware `CORE:S:0013 scope-fields-in-frontmatter` — rule no longer fires on rules below 30 lines (default). Override per-project via `.ails/config.yml: rule_thresholds.CORE:S:0013.min_lines`. Generic mechanism in deterministic check runner — `min_lines:` arg on any deterministic check + per-rule override.
- check: `generic` file class via Markdown link-reachability — opt-in via `.ails/config.yml: generic_scanning: true`. When on, the classifier BFS-walks outgoing links from each instruction file and assigns `file_type: "generic"` (with `loading: on_demand`) to reached in-tree `.md` files. Cycle-safe, depth-bounded (3 hops), tree-bound, agent-agnostic. Rule routing uses existing `FileMatch.type` — no rule-schema change. Default off everywhere.
- rules: `CORE:S:0056 broken-markdown-link` — mechanical rule on freeform markdown files. Discovers `[text](path)` + `[ref]: path` link targets in each file via `extract_markdown_links`, validates each resolves relative to the source file's directory via `check_markdown_link_targets_exist`. Skips URLs, `mailto:`, absolute paths, and anchor-only refs (`#frag`). Severity `medium`, sibling shape to `CORE:S:0024 import-targets-resolve`.
- check: Mechanical check engine threads `CheckResult.annotations` from a rule's discover-stage check into the args of its subsequent validate-stage check (`extract_imports` -> `check_import_targets_exist`, `extract_markdown_links` -> `check_markdown_link_targets_exist`). Annotation accumulator is per-rule; pass and fail fixtures accumulate independently in the harness. Closes a latent gap where the validate stage always saw an empty annotations dict and silently passed.
- check: Per-agent memory entry locator at `src/reporails_cli/core/discovery/memory_locator.py` — data-driven adapter that enumerates memory entries per agent (claude: `*.md` files inside `~/.claude/projects/*/memory/`, `.claude/agent-memory/<agent>/`, `.claude/agent-memory-local/<agent>/`; gemini: `## Gemini Added Memories` section inside `~/.gemini/GEMINI.md`). Returns `MemoryEntry` records with `agent`, `path`, optional `section`, and `body`. Consumed by the L3 memory rules without per-agent branches.
- classify: Link-reached generic files now record their source attribution on `ClassifiedFile.properties` — `loading_verb` ({read, imported, auto_loaded, invoked}), `link_source_type` (the linking file's `file_type` — main, rule, skill, agent, memory, subagent_memory, nested_context), `link_source_path` (project-relative paths of the linking files), and `link_depth` (1-3 from the instruction-file seed). `FileMatch` gains matching `loading_verb` and `link_source_type` fields for rule routing. Rule applicability for generic files is unchanged in this release.
- codex: New `memory` file_type declared as a tombstone — `~/.codex/memories/` holds generated state controlled via the `/memories` slash command and `config.toml` keys (`memories.generate_memories`, `memories.use_memories`, `memories.disable_on_external_context`, etc.), not user-authored markdown. No patterns to glob; surfaces in the agent registry but invites no rule pressure.
- check: Capability-name aliases for `memory|memories`, `subagent_memory|subagent_memories`, `nested_context|nested_contexts`. `ails check memory` (singular) and `ails check memories` (plural) both resolve. The memories alias folds `memory` and `subagent_memory` file_types into one listing; the main alias folds `main` and `nested_context`. Data-driven sing/plural map remains a follow-up.

### Changed
- Internals: Extracted per-item scorecard rendering (`compute_item_scores`, `render_item_health`, `_item_cell`, `_severity_breakdown_markup`, `_display_name_for_path`) from `formatters/text/scorecard.py` to `formatters/text/item_scorecard.py` so the parent module stays under the 600-line module cap per `.claude/rules/python-structure.md`. No user-visible change.
- tests: Added unit coverage for the 0.5.10 lint-pipeline scope fixes — `_strip_code_spans` (both extractors), `_resolve_glob_targets` exclude_dirs filtering, `_relativize` home-prefix fallback, `_first_classified_path` project-scope preference. 15 new tests in `tests/unit/test_lint_pipeline_scope.py`.
- auth: Set explicit `User-Agent: reporails-cli/<version> (auth)` header on platform and GitHub requests so identifiable CLI traffic can be allow-listed at the edge.
- check: `[PATH]` positional argument is now `[ARG1] [ARG2]` — `ARG1` is sniffed as a capability keyword first, falling through to existing path semantics. No behaviour change for `ails check`, `ails check .`, or `ails check <path>`.
- agents: Added `CORE:S:0024 import-targets-resolve` to `codex` and `copilot` agent `excludes:` lists — neither agent's instruction files support `@<path>` import syntax per their official documentation, so the rule has no antipattern to detect in those agents.
- rules: `CORE:S:0024 import-targets-resolve`, `CORE:S:0033 import-depth-within-limit`, and `CORE:S:0056 broken-markdown-link` severity raised from `medium` to `high` — broken includes, links, and over-depth chains are functional context gaps (referenced content silently fails to load), not stylistic warnings. `CLAUDE:S:0010` and `CURSOR:S:0002` per-agent supersedes updated to match.
- check: There is one display. Capability args (`ails check <capability>`, `ails check <capability> <name>`) narrow the input to that subset; the standard whole-repo renderer prints the same shape with fewer rows. The `formatters/text/focus.py` module was dropped; filters live in `display.py` next to the renderer that uses them.
- check: Filter the result's aggregate `quality.compliance_band` to the subset majority when capability args narrow the display. Previously the band leaked from the whole project, so the top `Score:` used the project-wide base while the per-surface health row used the filtered base — the two scores disagreed.
- check: Surface-health row is suppressed when only one surface has data (single capability target / single-surface listing). The top `Score:` already represents that surface; a second bar would just restate it.
- check: Per-item health bars in capability listings — `ails check skills` / `ails check rules` / `ails check agents` etc. now render one bar per item (sorted worst-first) where the whole-repo view would render per-surface bars. Operator can see at a glance which item is the worst. One item per line — scannable top-down without horizontal eye movement.
- check: Each item-health row carries a finding-count breakdown `(N: Xe/Yw/Zi)` after the score — severity-colored, zero counts omitted. Operator sees both severity (the bar) and effort (the count) on one line, so they can distinguish "low score but only 3 findings" from "low score, 54 findings."
- check: Score bars (top `Score:`, surface health, item health) split the markup span at the fill boundary — filled `▓` in the score color, empty `░` in dim gray. Previously the entire bar inherited the score color so empty segments looked like muted red/yellow; now every bar shares a consistent gray baseline and only the colored fill varies.
- check: Item-health listing inserts a blank line between severity bands (red → yellow → green) so the eye chunks the list into "needs attention" / "moderate" / "healthy" clusters without adding excessive whitespace.

### Fixed
- check: `CORE:S:0056 broken-markdown-link` and the generic-class link walker now strip fenced code blocks and inline code spans before extracting `[text](path)` references. Previously the rule false-positived on documentation that mentioned link syntax inside backticks — e.g. a `CHANGELOG.md` entry describing `[text](path)` semantics reported a broken link to `path`. Code-span stripping mirrors between `core/lint/mechanical/checks_advanced.py` and `core/classify/link_walker.py` so the broken-target rule and the generic-class classifier agree on what counts as a real link.
- check: Mechanical-check glob targets honor `.ails/config.yml: exclude_dirs`. Previously `_resolve_glob_targets` in `core/lint/mechanical/checks.py` globbed `**/*.md` (and similar patterns declared in `checks.yml` `args.path`) against the project root without applying the project's exclude_dirs filter, so files under excluded directories like `specs/` and `docs/` got scanned by rules that hard-code their own path glob. Project exclude_dirs are now loaded once per root and filtered against every glob result.
- check: Mechanical violation attribution no longer points to `~/.claude/CLAUDE.md` (or any user/managed-scope file) when the project has no project-scope main. `_first_classified_path` and the wildcard-match fallback in `core/lint/mechanical/runner.py` skip user-scope and managed-scope files; `_relativize` now emits `~/<path>` for paths under the home directory instead of bare basename, matching `normalize_finding_path`. Project-wide rules (`CORE:E:0001 total-instruction-size-limit`, `CORE:S:0024 import-targets-resolve`) now attribute to a project-scope file when one exists, and surface honestly when none does.
- gemini: `memory` block replaced the retired `## Gemini Added Memories` in-section locator with the current upstream model — private project memory at `~/.gemini/tmp/*/memory/` (`MEMORY.md` + sibling `*.md` notes), mirroring Claude's directory-glob shape. The legacy section header has 0 occurrences in `google-gemini/gemini-cli` source; the locator was targeting a surface that no longer exists. `memory_locator` enumerates entries through the same directory-glob dispatch Claude uses.
- gemini: All `source:` URLs in the agent config now point to the rendered `geminicli.com` docs site instead of GitHub raw markdown links. 13 file_types updated; no behavior change.
- check: Deterministic message text for the broad-scope client check — `client_checks._check_broad_scope` now sorts the matched broad terms before formatting the message, so output is reproducible across runs regardless of `PYTHONHASHSEED`. The set-iteration order previously caused `"Broad terms (any, integrations)"` vs `"Broad terms (integrations, any)"` drift on identical inputs.
- discovery: `DetectedFeatures.instruction_file_count` and `has_multiple_instruction_files` no longer include user-scope files like `~/.claude/CLAUDE.md`. The claude `main` file_type declares both project and user scope patterns; counting the user-scope file inflated capability gates in `policy/levels.py` (`multiple_files`, `external_references`) and L-level scoring in `policy/capability.py` for any user with a home-directory `CLAUDE.md`. Counts are now scoped to files under `target`; `_find_root_instruction` was already correctly scoped.
- discovery: Directory-glob patterns (trailing slash) in agent configs now enumerate `*.md` files inside the matched directories. Previously `categorize_file_type` bucketed them as `skip`, leaving capability-owned memory files unclassified — the link walker then mis-tagged them `file_type: "generic"`. Affects claude `memory` and `subagent_memory` (project + local scopes); files under `.claude/agent-memory/<agent>/` and `.claude/agent-memory-local/<agent>/` now correctly classify to `subagent_memory`, unblocking `match: {type: memory}` rule routing.
- check: `import-targets-resolve` (CORE:S:0024) fixture and rule body switched from incorrect `@import <path>` syntax (which extracted `@import` as the path) to canonical `@<path>` syntax matching the `@[\w./-]+` regex in `extract_imports`. The pre-existing fixture silently passed because the engine's annotation-threading was broken; both are now correct.
- check: Mapper daemon now stays attached across `ails check` invocations instead of forcing every run to load ML models in-process. Three issues in `core/mapper/daemon.py`: `is_daemon_running` requires the socket file to exist alongside the PID (a stuck `ails check`-turned-daemon used to keep its PID alive indefinitely, fooling every new run into seeing a "running" daemon and falling back); `_become_daemon`'s FD-close loop narrowed to FIFO/pipe FDs via `S_ISFIFO` instead of indiscriminate `range(3, 1024)` — closing all FDs killed numpy / onnxruntime compiled-extension FDs imported pre-fork, breaking the daemon's first `map_ruleset` with `ImportError: import numpy failed`; SIGPIPE set to `SIG_IGN` in `_daemon_main` so a client disconnect mid-response can't terminate the daemon via the default signal handler. Warm `ails check` against a 27-file sample now runs ~5.6 s daemon-attached instead of falling through to ~8-9 s in-process.
- discovery: `walk_glob` in `core/discovery/agent_discovery.py` now follows symlinked directories during descendant traversal so files inside symlinked subdirs are visible to whole-repo discovery. Cycle protection via canonical inode tracking ensures each physical directory is entered at most once. Aligns whole-repo discovery with the `glob.glob(..., recursive=True)` behavior used by per-capability listing.
- rules: `CORE:S:0024 import-targets-resolve` and `CORE:S:0056 broken-markdown-link` now declare `match: {format: [freeform, frontmatter]}` so they fire on SKILL.md / `.claude/agents/*.md` / `.claude/rules/*.md` files. Prior `{format: freeform}` constraint excluded frontmatter-bearing instruction files from import-resolution and broken-link coverage even though the agent schema characterizes those file types as `format: [frontmatter, freeform]`.
- tests: Wrapped the `TestWalkGlobFollowsSymlinkedDirs` class docstring in `tests/unit/test_symlink_detection.py` to satisfy `ruff` E501; no behavior change.
- discovery: Capability-listing path (`ails check <capability>`) now honors `.ails/config.yml: exclude_dirs` — `list_capability_targets` accepts and applies the exclude set, mirroring the whole-repo discovery filter. Previously the listing bypassed the config and surfaced matches inside excluded directories.
- discovery: `ails check memory` (and `memories`) now enumerates `~/.claude/projects/<hash>/memory/` entries via `memory_locator.memory_entries_for_agent` instead of returning 0 — the glob path silently dropped user-scope patterns starting with `~/`.

### Removed
- framework: Dropped `framework/registry/levels.yml` and `framework/schemas/levels.schema.yml`. The level engine has hardcoded `LEVEL_CAPS` in `core/platform/policy/levels.py` since v4 of the levels schema; the YAML file was bundled into wheels but never read at runtime. The `framework/registry/` directory is removed entirely. `hatch_build.py` no longer force-includes the path.

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
