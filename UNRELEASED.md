# Unreleased

### Added
- auth: Typed `PlatformUnavailableError` raised when `/api/auth/client-id` returns a non-JSON body, replacing the silent fall-through that surfaced as a misleading "OAuth not configured" message.
- check: Per-capability targeting — `ails check <capability> <name>` resolves to a focused report on one capability target (skill, rule, agents, main, etc.), and `ails check <capability>` lists available targets with per-target scores. Capability vocabulary is read from the detected agent's `framework/rules/<agent>/config.yml` `file_types:`; supports singular and plural forms (skill/skills, rule/rules, agent/agents).
- check: Focus-mode output layout for capability runs — single-file score, findings grouped by rule with line refs, "Next" action pointer toward the highest-frequency rule. Subagent targets expand to include skills declared in their `skills:` frontmatter.
- check: `Top rules (by finding count)` block in the whole-repo scorecard, ranked across all findings.
- check: `top_rules` array in `-f json` output; `focus` envelope in capability-mode JSON describes the targeted capability, name, agent, and paths.
- check: Size-aware `CORE:S:0013 scope-fields-in-frontmatter` — rule no longer fires on rules below 30 lines (default). Override per-project via `.ails/config.yml: rule_thresholds.CORE:S:0013.min_lines`. Generic mechanism in deterministic check runner — `min_lines:` arg on any deterministic check + per-rule override.
- check: `generic` file class via Markdown link-reachability — opt-in via `.ails/config.yml: generic_scanning: true`. When on, the classifier BFS-walks outgoing links from each instruction file and assigns `file_type: "generic"` (with `loading: on_demand`) to reached in-tree `.md` files. Cycle-safe, depth-bounded (3 hops), tree-bound, agent-agnostic. Rule routing uses existing `FileMatch.type` — no rule-schema change. Default off everywhere.

### Changed
- auth: Set explicit `User-Agent: reporails-cli/<version> (auth)` header on platform and GitHub requests so identifiable CLI traffic can be allow-listed at the edge.
- check: `[PATH]` positional argument is now `[ARG1] [ARG2]` — `ARG1` is sniffed as a capability keyword first, falling through to existing path semantics. No behaviour change for `ails check`, `ails check .`, or `ails check <path>`.

### Fixed
- check: Deterministic message text for the broad-scope client check — `client_checks._check_broad_scope` now sorts the matched broad terms before formatting the message, so output is reproducible across runs regardless of `PYTHONHASHSEED`. The set-iteration order previously caused `"Broad terms (any, integrations)"` vs `"Broad terms (integrations, any)"` drift on identical inputs.
- discovery: `DetectedFeatures.instruction_file_count` and `has_multiple_instruction_files` no longer include user-scope files like `~/.claude/CLAUDE.md`. The claude `main` file_type declares both project and user scope patterns; counting the user-scope file inflated capability gates in `policy/levels.py` (`multiple_files`, `external_references`) and L-level scoring in `policy/capability.py` for any user with a home-directory `CLAUDE.md`. Counts are now scoped to files under `target`; `_find_root_instruction` was already correctly scoped.

### Removed
