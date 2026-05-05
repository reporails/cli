# Unreleased

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
