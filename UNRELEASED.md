# Unreleased

### Added

- Tooling: `uv run poe specs_check` validates internal subsystem coverage (declared subsystems exist, each spec is within line-budget, modules colocate under one subpackage); `uv run poe spec_drift` flags potentially stale design docs whose source has been edited more recently
- Tooling: expanded `pytest` marker taxonomy in `pyproject.toml` for granular test selection (lane, cost, subsystem) with new poe tasks `test_fast`, `test_arch`, `test_contracts`, `test_markers`
- Tooling: every `tests/*` test function now carries pytest lane (`unit`/`integration`/`e2e`) + subsystem (`subsys_*`) markers; `check_test_markers.py` enforces tagging on every `qa_fast` run, enabling `pytest -m subsys_caching` and similar slicing
- Tooling: hexagonal platform substrate skeleton bootstrapped at `core/platform/{contract,dto,policy,adapters,runtime,config,observability,utils}` with report-only architecture tests guarding pure-layer purity and adapter boundary (`tests/unit/architecture/`)

### Changed

- Internals: relocated `core/{analytics,bootstrap,config,utils}.py` into the hexagonal platform substrate (`core/platform/{observability,config,utils}/`); no user-facing behavior change
- Internals: relocated `core/{models,results}.py` to `core/platform/dto/` and `core/{applicability,levels}.py` to `core/platform/policy/`; pure-layer files now populated and architecture tests catch any forbidden cross-layer import
- Internals: relocated `core/{api_client,payload,registry,rule_builder}.py` to `core/platform/adapters/` and `core/{engine_helpers,merger}.py` to `core/platform/runtime/`; substrate now covers all eight layers
- Internals: `tests/unit/architecture/test_core_purity.py` and `test_adapter_boundary.py` now run in fail mode; two documented allowlist entries track pending cleanups (impure filesystem-detection helpers and `RulesetMap` location), and any new forbidden cross-layer import blocks the build
- Internals: consolidated caching subsystem into `core/cache/` subpackage (`cache.py` → `cache/__init__.py`, `check_cache.py` → `cache/check_cache.py`, `mapper/map_cache.py` → `cache/map_cache.py`); resolves the long-standing co-location warning where cache files spanned two parent directories
- Internals: consolidated five subsystems into named subpackages — `core/funnel/`, `core/classify/`, `core/heal/`, `core/discovery/`, `core/lint/` — each matching its design-spec boundary; specs/sys/cli/DISCOVERY.md added for the newly-named discovery subsystem
- Internals: extracted `RulesetMap` and supporting dataclasses (`Atom`, `FileRecord`, `ClusterRecord`, `RulesetSummary`, `InlineToken`, `TopicCluster`) from `mapper/mapper.py` to `core/platform/dto/ruleset.py`; adapters now import wire-format types from the pure DTO layer and the adapter-boundary architecture test no longer needs an allowlist entry
- Funnel: Rate-limit CTA now surfaces a "Try again in ~N min." hint when the server returns an accurate `reset_in`, between the limit blurb and the upgrade prompt
- Funnel: CTA and bug-report URLs render as OSC 8 terminal hyperlinks with a short clickable label (`github.com/reporails/cli/issues/new`) instead of dumping the full percent-encoded prefilled URL; falls back to the short label on terminals without hyperlink support
- Funnel: demoted the "Could not parse N response body" and "Server returned N for tier=" stderr warnings to debug logging so they no longer print above the diagnostic report; reworded the `unknown_error` CTA to `Diagnostics server returned HTTP <code>` (honest about what we know without claiming the body is unparseable)
- Display: file rows now annotate duplicates with `(+alias)` labels — symlinked surfaces show the differing path component (e.g. `mintlify (+.claude)`), same-directory content-identical pairs show the alternate filename (e.g. `AGENTS.md (+CLAUDE.md)`)

### Fixed

- Check: `frontmatter_valid_glob` no longer crashes on comma-separated `paths:` values; each entry is now split and validated individually, and invalid glob syntax surfaces as a structured check failure instead of an unhandled exception
- Discovery: skill and rule files that appear under multiple agent surfaces via symlinks (e.g. `.claude/skills/` → `.agents/skills/`) are now collapsed to one canonical entry, eliminating duplicate findings and inflated scoring

### Removed
