# Changelog

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
