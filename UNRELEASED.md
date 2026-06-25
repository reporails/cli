# Unreleased

### Added

- check: inline per-line finding suppression. Mark a single reviewed line with `<!-- ails-disable-line CORE:C:0047 -->` to silence just that one rule on just that line, while the rule keeps firing everywhere else. The directive is an invisible HTML comment, must name the rule (space/comma-separate several), and never changes how the rest of the line is analyzed. See `docs/configuration.md`.
- testing: added internal regression coverage to keep `ails check` output stable across refactors.
- testing: added an architecture check that keeps error handling at the network boundary consistent, so faults surface clearly instead of being silently swallowed.
- testing: opt-in live-network lane exercising the `ails auth login` activation path so first-contact auth regressions surface in CI rather than at a new user.

### Changed

- rules: renamed the Google agent rule pack and registry entry from `gemini` to `antigravity`, following Google's 2026-06-18 retirement of the Gemini CLI in favor of the Antigravity CLI. The pack still validates legacy `GEMINI.md` / `~/.gemini/` files for backward-compat and now also recognizes Antigravity's `AGENTS.md` primary and `.agents/` skills layout. `ails check` reports the agent as `antigravity`; the five implemented agents are now claude, codex, copilot, cursor, antigravity.
- testing: normalized code formatting in two test modules (no behavior change).

### Fixed

- check: a neutral sentence is no longer flagged as ambiguous when the only instruction-like word sits inside a Markdown link label, a citation reference, or a `code span` — those are references, not instructions. Genuine inline instruction language in a neutral sentence still surfaces. Reduces false positives on documentation prose that links to or cites a rule by name.
- auth: clearer errors when the credentials or config file can't be read — a corrupt file now produces a visible warning and the session continues with anonymous access, instead of a silent tier downgrade.
- performance: `ails check` is substantially faster on large projects, with identical output.
- auth: `ails auth login` now identifies an upstream edge challenge (e.g. a Cloudflare interstitial in front of the auth endpoint) as the real cause instead of reporting a generic HTTP error or a misleading "OAuth not configured" message. Both the client-id lookup and the token-exchange step recognize the challenge page and tell you it is not fixable in the CLI — retry shortly or contact support.

### Removed
