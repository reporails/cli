# Unreleased

### Added

- check: `ails check referenced` — new capability listing surface for `[text](path)`-reached markdown files (`file_type: referenced`). Virtual-capability path: agent-agnostic (markdown links are universal), enumerates classifier output rather than agent-config globs. Requires `.ails/config.yml: generic_scanning: true` to populate; otherwise empty. Per `cli/specs/plans/0.5.11-referenced-capability-carve-out.md` § Phase 4.

### Changed

- classify: Link-reached files split into two file types — `[text](path)` markdown-link reach classifies the target as `file_type: referenced` with `loading: discoverable`; `@<path>` import reach keeps `file_type: generic` with `loading: session_start`/`on_demand` per source eagerness. Mixed reach (both `@` and link from any source) routes to `generic` — the import path's auto-load guarantee dominates the link-only path's discoverability. Matches the actual harness loading model: only `@`-imported content enters context budget without an explicit `Read`. Per `cli/specs/plans/0.5.11-referenced-capability-carve-out.md`.

### Fixed

- [Lint]: Gate user-scope `~/...` rendering in mechanical-check attribution on the classifier's `precedence: user` property (read from agent config patterns) instead of path-prefix heuristics, so Windows tmp paths under the user profile no longer render with a `~/` prefix.

### Removed
