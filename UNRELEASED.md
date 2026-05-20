# Unreleased

### Added

- rules: `ails rules` — new subcommand exposing the framework rule registry as a queryable surface. `ails rules list` enumerates every rule with filters for capability, agent, and severity. `ails rules for skill | agent | rule | main` returns the workflow-ordered preflight checklist for authoring a file of that capability (sorted by category: structure → direction → coherence → efficiency → maintenance → governance; severity as tiebreaker). `ails rules explain <id>` returns the rule body plus Pass / Fail examples. Three output formats: `text` (compact), `md` (rich, Pass / Fail blocks by default; `--no-examples` opt-out for shorter context payload), `json` (structured). The markdown form is designed to pipe directly into an AI authoring agent's prompt so it writes rule-compliant content from the start rather than patching findings after `ails check`.
- check: `ails check referenced` — new capability listing surface for `[text](path)`-reached markdown files (`file_type: referenced`). Virtual-capability path: agent-agnostic (markdown links are universal), enumerates classifier output rather than agent-config globs. Requires `.ails/config.yml: generic_scanning: true` to populate; otherwise empty.

### Changed

- Internals: New `core/platform/adapters/rules_query.py` adapter (load + filter + sort + fence-aware Pass/Fail extraction) backs `ails list checks`. CLI surface lives at `interfaces/cli/checks_command.py` as a Typer sub-app under the `list` verb. 18 unit tests + 9 integration tests cover loader / filter / sort / command / examples.
- classify: Link-reached files split into two file types — `[text](path)` markdown-link reach classifies the target as `file_type: referenced` with `loading: discoverable`; `@<path>` import reach keeps `file_type: generic` with `loading: session_start`/`on_demand` per source eagerness. Mixed reach (both `@` and link from any source) routes to `generic` — the import path's auto-load guarantee dominates the link-only path's discoverability. Matches the actual harness loading model: only `@`-imported content enters context budget without an explicit `Read`. Per `cli/specs/plans/0.5.11-referenced-capability-carve-out.md`.

### Fixed

- [Lint]: Gate user-scope `~/...` rendering in mechanical-check attribution on the classifier's `precedence: user` property (read from agent config patterns) instead of path-prefix heuristics, so Windows tmp paths under the user profile no longer render with a `~/` prefix.
- check: `ails check main` no longer folds subdirectory CLAUDE.md / `nested_context` / `child_instruction` files into the `main` umbrella. The capability now lists only root-level family (`main` + `override`); use `ails check nested_context` or `ails check child_instruction` to enumerate subdir CLAUDE.md. Capability-listing now reuses the classifier's `scope`/`loading` semantics so `**/CLAUDE.md` partitions correctly between root and nested.
- check: `ails check <file>` narrows the display to the named file so the headline `Score:`, surface-health bars, and per-file panels reflect only what the operator asked about. Previously, discovery enumerated user-scope `~/.claude/CLAUDE.md` alongside the project file, inflating finding totals with entries from a path the operator hadn't named.

### Removed
