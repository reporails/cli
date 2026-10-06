# Reporails CLI (v0.6.0)

> **AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 120+ rules across six rule packs (core + per-agent). Supports Antigravity, Claude, Codex, Copilot, and Cursor.**
> 
> *Beta phase - moving fast, feedback welcome.*

## Quick Start

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

No install, no account. The headline is a single **Quality** score (the analysis service's verdict on how well-formed your instructions are); fix the findings that move it, run again, watch it climb:

```
Reporails — Diagnostics

  ┌─ Main (1)  6 directive / 1 constraint · 30% prose
  │ CLAUDE.md  6 dir / 1 con · 30% prose
  │   ✗       Unresolved imports: docs/setup.md  CORE:S:0024
  │   ⚠       Missing directory layout — show the project structure with a tre…  CORE:C:0035
  │     ... and 19 more
  │     6 vague · 7 brief · 1 weak
  │     ⊕ 2 Pro diagnostics — topic overlap, unbalanced topics
  │
  └─ 35 findings

  ┌─ Rules (1)  4 directive · 20% prose
  │ testing  4 dir · 20% prose
  │   ⚠       No frontmatter block found  CLAUDE:S:0012
  │   ⚠       Missing frontmatter block — start with --- delimited YAML frontm…  CORE:S:0006
  │     ... and 1 more
  │     4 vague · 4 brief
  │     ⊕ 1 Pro diagnostics — topic overlap
  │
  └─ 11 findings

  ── Cross-file ────────────────────────────────────────

  ⚠  .claude/rules/testing.md ↔ CLAUDE.md — 3 overlaps
  ⚠  .claude/rules/testing.md ↔ CLAUDE.md — 1 repetition

  Line-level detail → sign in with ails auth login, then upgrade to Pro

  ── Summary ─────────────────────────────────────────

  Quality   1.0 / 10  ▓▓░░░░░░░░░░░░░░░░░░  (1.0s)
  Fix now   1 error. Start with CORE:S:0024.
  Findings  46 total · -v to list every one
  Agent: Claude
  Level: L3 Scoped

  Scope:
    instructions: 10 directive / 4 prose (27%)
                  1 constraint

  Main (1):  ▓▓░░░░░░░░░░░░░   1.0  35 findings · 1 error
  Rules (1): ▓▓░░░░░░░░░░░░░   1.0  11 findings

  Top rules (by finding count):
    CORE:E:0004   x11  warn  Instruction Elaboration
    CORE:C:0042   x10  warn  Specificity Gap
    CLAUDE:S:0012 x2   warn  Path Scope Declared
    CORE:C:0005   x1   warn  Testing Framework Documented

  + 3 Pro diagnostics (3 warnings)
  1 cross-file repetition
  1 element pair overlaps in topic — keep each topic in one file

  Pro adds the remedies and the order to apply them.
  → sign in with ails auth login, then upgrade to Pro
```

## Install permanently

```bash
npx @reporails/cli install
# or
uvx --from reporails-cli ails install
```

Puts `ails` on your PATH, installs the reporails plugin into Claude Code and Codex when they are on your machine, and prints the install steps for the other supported agents (also listed in [Agent Support](https://github.com/reporails/cli/blob/main/docs/agent-support.md#plugin-support)). `ails install --project` installs the plugin for the current repository only, shared with collaborators through its Claude Code settings; Codex installs for your user. `ails update` upgrades `ails` and refreshes the plugin in each agent that has it. With Pro, the step after install is `/reporails:ails heal` in Claude Code, which rewrites your instruction files.

## Free vs Pro

Anonymous mode needs no account, and signing in is free. Anonymous and signed-in free accounts share the same rate and payload caps and the same full diagnosis — every finding, the score, and the local deterministic fixes — and signing in additionally lets you apply fixes with `ails check --heal`. Pro is the paid subscription: it raises the rate and payload caps and unlocks the remedies (what to change, where, and how), the exact line of each cross-file repetition and topic overlap, and the ordered remediation workflow your coding agent runs end to end.

```bash
# GitHub Device Flow - authorize in browser
ails auth login
```

Full breakdown: [Tiers and Limits](https://github.com/reporails/cli/blob/main/docs/tiers.md).

## In CI

Run on every PR so instruction-quality regressions (vague or buried instructions, oversized files, weak reinforcement, instructions repeated across files) get caught the same way test or lint regressions do — before merge, not after a teammate's agent has been silently misbehaving for a week.

```yaml
- uses: reporails/cli/action@0.6.0
  with:
    api-key: ${{ secrets.REPORAILS_API_KEY }}   # optional - a Pro key unlocks the full diagnostic detail
    strict: "true"                              # exit 1 if any rule fires
    min-score: "7.0"                            # exit 1 if Quality < 7.0
```

Capture your API key with `ails auth token` and store it as `REPORAILS_API_KEY` in your CI secret store. See [Configuration → Authentication](https://github.com/reporails/cli/blob/main/docs/configuration.md#authentication).

The action keeps the analysis model (~275 MB) in the repository's Actions cache: the first run downloads it, and later runs restore it instead of downloading it again, even when the check fails. Running `ails` directly in a workflow? See [Configuration → Caching the model in CI](https://github.com/reporails/cli/blob/main/docs/configuration.md#caching-the-model-in-ci).

## Documentation

- [Getting Started](https://github.com/reporails/cli/blob/main/docs/getting-started.md) - install, first run, what the output means
- [Agent Support](https://github.com/reporails/cli/blob/main/docs/agent-support.md) - which agents are recognized and what's covered
- [Tiers and Limits](https://github.com/reporails/cli/blob/main/docs/tiers.md) - Free vs Pro, what each tier includes
- [Configuration](https://github.com/reporails/cli/blob/main/docs/configuration.md) - disabling rules, project / global config, exclude paths
- [Score Guide](https://github.com/reporails/cli/blob/main/docs/score-guide.md) - how the score is built and what it tells you
- [Capability Levels](https://github.com/reporails/cli/blob/main/docs/capability-levels.md) - the L0-L7 ladder and what each level requires
- [Rules CLI](https://github.com/reporails/cli/blob/main/docs/rules-cli.md) - `ails rules list --capability=skill` and friends — preflight rules before authoring
- [FAQ](https://github.com/reporails/cli/blob/main/docs/faq.md) - common questions

## Built and validated for

- **Antigravity** — [Google](https://antigravity.google)
- **Claude** — [Anthropic](https://github.com/anthropics)
- **Codex** — [OpenAI](https://github.com/openai)
- **Copilot** — [GitHub](https://github.com/github)
- **Cursor** — [Anysphere](https://github.com/cursor)

## License

[BUSL 1.1](https://github.com/reporails/cli/blob/main/LICENSE) - converts to Apache 2.0 three years after each release.

The analysis model files are licensed separately under the [Reporails Model Licence](https://github.com/reporails/cli/blob/main/LICENSE-weights).
