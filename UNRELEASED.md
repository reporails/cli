# Unreleased

### Added

- check: inline per-line finding suppression. Mark a single reviewed line with `<!-- ails-disable-line CORE:C:0047 -->` to silence just that one rule on just that line, while the rule keeps firing everywhere else. The directive is an invisible HTML comment, must name the rule (space/comma-separate several), and never changes how the rest of the line is analyzed. See `docs/configuration.md`.
- testing: added internal regression coverage to keep `ails check` output stable across refactors.
- testing: added an architecture check that keeps error handling at the network boundary consistent, so faults surface clearly instead of being silently swallowed.
- testing: opt-in live-network lane exercising the `ails auth login` activation path so first-contact auth regressions surface in CI rather than at a new user.
- testing: the suite now runs against an isolated home directory, so a contributor's machine-wide config (`~/.reporails/config.yml`, `~/.codex/`, `~/.claude/`) no longer leaks into agent-detection tests — they pass or fail the same way locally as in CI. Includes a regression test pinning that a global `~/.codex/config.toml` cannot hijack detection of an `AGENTS.md`-only project.
- testing: the end-to-end smoke suite now runs in CI on every push. It is hermetic — diagnostics run offline (no network), home is isolated, and the few assertions that can only be observed through the bundled mapper model skip cleanly on the model-free runner — so smoke regressions are caught in CI instead of shipping green.
- testing: the rule-library lint pass (`ails test --lint`) now runs as part of the QA gate, so a duplicate rule ID anywhere in the rule library or a malformed rule fails the gate instead of slipping through unnoticed.
- testing: new CI-gated coverage for three previously-untested behaviors — `ails check --heal --dry-run` leaving files unmodified, the friendly "Path not found" error on a bare keyword that is neither a path nor a capability, and multi-target `ails check` (several targets in one invocation) scoping the scan to exactly those targets.
- testing: hardened that new coverage — the multi-target test now asserts against a file the scan would otherwise discover, so it genuinely proves out-of-target scoping, and the `--heal --dry-run` no-mutation test documents that its full assertion runs only where the bundled model is present.

### Changed

- rules: renamed the Google agent rule pack and registry entry from `gemini` to `antigravity`, following Google's 2026-06-18 retirement of the Gemini CLI in favor of the Antigravity CLI. The pack still validates legacy `GEMINI.md` / `~/.gemini/` files for backward-compat and now also recognizes Antigravity's `AGENTS.md` primary and `.agents/` skills layout. `ails check` reports the agent as `antigravity`; the five implemented agents are now claude, codex, copilot, cursor, antigravity.
- testing: normalized code formatting in two test modules (no behavior change).
- check: `ails check --heal` now requires you to name what to fix. A whole-project heal — a bare `--heal`, or `ails check . --heal` / `ails check ./ --heal` — is refused; pass an explicit target (`ails check CLAUDE.md --heal`), preview everything with `--dry-run`, or opt into a whole-project rewrite with the new `--cwd` flag. `--heal` also never writes through an in-tree symlink whose real file lies outside the named target, so a scoped heal cannot modify files outside its scope. Prevents accidental project-wide and out-of-scope rewrites.
- check: applying fixes now requires an account. The diagnosis stays free for everyone, but `--heal` (apply or `--dry-run` preview) needs sign-in — anonymous users get the full diagnosis plus a prompt to run `ails auth login`. This keeps the free experience honest: the diagnosis names what to fix; the fix is the account feature.
- explain: `ails explain <rule>` now shows the rule's Pass / Fail examples, matching `ails rules -f md`. Both surfaces draw examples from the same fence-aware extractor, and both now name an absent example block ("no Pass / Fail examples") instead of silently omitting it.
- json: `-f json` and the `--format github` trailing JSON now emit canonical rule IDs (e.g. `CORE:S:0039`) for findings that previously carried a bare client-side token like `format` or `orphan`, matching the text output. The raw token is preserved under a new `label` key when it differs, so machine baselines keyed on it stay stable. As a result those findings now carry a populated `category` and join the per-surface category breakdown, and `top_rules` is keyed by canonical ID. (The `ambiguous_charge` classifier-confidence marker has no canonical rule and intentionally stays label-only.)
- rules: a rule's check can now declare `project_scope: true` in `checks.yml` to be skipped on a narrowed (single-target) run where a whole-project aggregate is meaningless — previously this was hard-coded in the engine, so adding such a rule required a code change. No change to default whole-project scans.
- help: the `npx @reporails/cli` help output now lists the `ails rules` command.
- check: the collapsed lower-priority findings row no longer claims those findings "won't move your score yet" — it now reads `+N lower-priority · -v to list`. The old wording implied the deferred findings would move the score once the higher-priority ones were fixed, which overpromised; the row simply marks the collapsed tail.

### Fixed

- check: a neutral sentence is no longer flagged as ambiguous when the only instruction-like word sits inside a Markdown link label, a citation reference, or a `code span` — those are references, not instructions. Genuine inline instruction language in a neutral sentence still surfaces. Reduces false positives on documentation prose that links to or cites a rule by name.
- auth: clearer errors when the credentials or config file can't be read — a corrupt file now produces a visible warning and the session continues with anonymous access, instead of a silent tier downgrade.
- performance: `ails check` is substantially faster on large projects, with identical output.
- auth: `ails auth login` now identifies an upstream edge challenge (e.g. a Cloudflare interstitial in front of the auth endpoint) as the real cause instead of reporting a generic HTTP error or a misleading "OAuth not configured" message. Both the client-id lookup and the token-exchange step recognize the challenge page and tell you it is not fixable in the CLI — retry shortly or contact support.
- check: a whole-project scan no longer lets your machine-wide agent config decide which agent a repository is. A global home-directory file such as `~/.codex/config.toml` could make `ails check` treat a project that only has an `AGENTS.md` as that specific agent's project, narrowing the findings to that agent's rules instead of the cross-agent core set. Discovery now ignores home-scope (`~/...`) paths during a repository scan; those surfaces remain reachable only when you target them explicitly (e.g. `ails check subagent_memory`).
- check: per-surface health bars stay column-aligned when a surface name is long and its file count reaches two digits — the name column now sizes to the widest label in the set instead of a fixed width.
- check: targeting a directory (`ails check <dir>`) no longer drops instruction files that are symlinks pointing outside that directory; an in-tree symlinked file under the target is now scanned.
- update: rule-framework archive extraction is forward-compatible with Python 3.14's stricter tar handling (uses the safe `data` extraction filter).

### Removed

- internal: removed two unused output-rendering helpers; no change to `ails check` output.
- internal: pruned several unused internal modules (a feature-summary helper, a display stub, a dead init path, a rules-path resolver, and an orphan-feature detector); no user-facing behavior change.
