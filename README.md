# Reporails CLI (v0.5.12)

> **AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 120+ rules across six rule packs (core + per-agent). Supports Claude, Codex, Copilot, Cursor, and Gemini.**
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

  ┌─ Main (1)  10 directive / 1 constraint · 71% prose
  │ CLAUDE.md  10 dir / 1 con / 1 amb · 71% prose
  │   ✗       Missing tech stack declaration — list languages, frameworks, runtimes  CORE:C:0034
  │       → Name the languages, frameworks, and runtimes the project targets.
  │   ⚠       'pytest' should be in backticks (×3)  CORE:E:0003
  │       → Wrap in backticks: `pytest`
  │     ◦ +4 lower-priority (won't move your score yet) · -v to list
  │     ⊕ 6 Pro diagnostics (1 error) — isolated instructions, buried directives
  │
  └─ 12 findings

  ── Summary ────────────────────────────────────────────────────────

  Quality   6.4 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░  (4.1s)
  Findings 3 errors · 38 warnings · 12 info
  Agent: Claude
  Level: L4 Delegated

  Scope:
    instructions: 64 directive / 102 prose (61%)
                  18 constraint / 4 ambiguous

  Main (1):    ▓▓▓▓▓▓▓▓▓░░░░░░   6.4  1 err    Rules (2):   ▓▓▓▓▓▓▓▓▓▓▓▓░░░   7.9
  Skills (3):  ▓▓▓▓▓▓▓▓▓▓▓░░░░   7.2           Agents (1):  ▓▓▓▓▓▓▓▓▓▓░░░░░   6.6

  + 41 Pro diagnostics (1 error · 32 warnings) — sign in for line numbers + fix coordinates
```

## Install permanently

```bash
npx @reporails/cli install
# or
uvx --from reporails-cli ails install
```

Puts `ails` on your PATH.

## Anonymous vs signed

Anonymous mode needs no account. Signing in raises the rate / payload caps and unlocks per-finding fix text and exact cross-file conflict locations.

```bash
# GitHub Device Flow - authorize in browser
ails auth login
```

Full breakdown: [Tiers and Limits](https://github.com/reporails/cli/blob/main/docs/tiers.md).

## In CI

Run on every PR so instruction-quality regressions (contradictions, oversized files, weak reinforcement) get caught the same way test or lint regressions do — before merge, not after a teammate's agent has been silently misbehaving for a week.

```yaml
- uses: reporails/cli/action
  with:
    api-key: ${{ secrets.REPORAILS_API_KEY }}   # optional - sign-in for full diagnostic detail
    strict: "true"                              # exit 1 if any rule fires
    min-score: "7.0"                            # exit 1 if Quality < 7.0
```

Capture your API key with `ails auth token` and store it as `REPORAILS_API_KEY` in your CI secret store. See [Configuration → Authentication](https://github.com/reporails/cli/blob/main/docs/configuration.md#authentication).

## Documentation

- [Getting Started](https://github.com/reporails/cli/blob/main/docs/getting-started.md) - install, first run, what the output means
- [Agent Support](https://github.com/reporails/cli/blob/main/docs/agent-support.md) - which agents are recognized and what's covered
- [Tiers and Limits](https://github.com/reporails/cli/blob/main/docs/tiers.md) - anonymous vs signed in, what each mode includes
- [Configuration](https://github.com/reporails/cli/blob/main/docs/configuration.md) - disabling rules, project / global config, exclude paths
- [Score Guide](https://github.com/reporails/cli/blob/main/docs/score-guide.md) - how the score is built and what it tells you
- [Capability Levels](https://github.com/reporails/cli/blob/main/docs/capability-levels.md) - the L0-L7 ladder and what each level requires
- [Rules CLI](https://github.com/reporails/cli/blob/main/docs/rules-cli.md) - `ails rules list --capability=skill` and friends — preflight rules before authoring
- [FAQ](https://github.com/reporails/cli/blob/main/docs/faq.md) - common questions

## Built and validated for

- **Claude** — [Anthropic](https://github.com/anthropics)
- **Codex** — [OpenAI](https://github.com/openai)
- **Copilot** — [GitHub](https://github.com/github)
- **Cursor** — [Anysphere](https://github.com/cursor)
- **Gemini** — [Google](https://github.com/google-gemini)

## License

[BUSL 1.1](LICENSE) - converts to Apache 2.0 three years after each release.
