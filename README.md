# Reporails CLI (v0.5.6)

> **AI Instruction Diagnostics for coding agents. Validates the entire agentic instruction system against 92+ rules across six categories. Supports Claude, Codex, Copilot, Cursor, and Gemini.**
> 
> *Beta phase - moving fast, feedback welcome.*

## Quick Start

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

No install, no account. Actionable findings in seconds - fix them, run again, watch the score improve:

```
Reporails - Diagnostics

  ┌─ Main (4)  61 directive / 9 constraint · 71% prose
  │ CLAUDE.md  10 dir / 1 con / 1 amb · 71% prose
  │           Missing tech stack declaration - list languages, frameworks, and runtimes  CORE:C:0034
  │           Missing MCP documentation - describe MCP server configuration if applicable  CORE:C:0027
  │     ... and 3 more
  │     4 brief · 1 orphan
  │
  └─ 181 findings

  [⋯ Agents (3) · Skills (10) · Rules (13)  +318 findings ⋯]

  ── Summary ────────────────────────────────────────────────────────

  Score: 7.3 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░  (3.9s)
  Agent: Claude

  Scope:
    instructions: 277 directive / 448 prose (56%)
                  75 constraint / 10 ambiguous

  Main (4):     ▓▓▓▓▓▓▓▓▓▓░░░░░   6.9    Rules (13):   ▓▓▓▓▓▓▓▓▓▓▓▓░░░   7.9
  Skills (10):  ▓▓▓▓▓▓▓▓▓▓▓░░░░   7.2    Agents (3):   ▓▓▓▓▓▓▓▓▓▓░░░░░   6.9

  499 findings · 5 errors · 416 warnings · 70 info
  2 cross-file conflicts · 7 cross-file repetitions
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
    min-score: "7.0"                            # exit 1 if score < 7.0
```

Capture your API key with `ails auth token` and store it as `REPORAILS_API_KEY` in your CI secret store. See [Configuration → Authentication](https://github.com/reporails/cli/blob/main/docs/configuration.md#authentication).

## Documentation

- [Getting Started](https://github.com/reporails/cli/blob/main/docs/getting-started.md) - install, first run, what the output means
- [Agent Support](https://github.com/reporails/cli/blob/main/docs/agent-support.md) - which agents are recognized and what's covered
- [Tiers and Limits](https://github.com/reporails/cli/blob/main/docs/tiers.md) - anonymous vs signed in, what each mode includes
- [Configuration](https://github.com/reporails/cli/blob/main/docs/configuration.md) - disabling rules, project / global config, exclude paths
- [Score Guide](https://github.com/reporails/cli/blob/main/docs/score-guide.md) - how the score is built and what it tells you
- [FAQ](https://github.com/reporails/cli/blob/main/docs/faq.md) - common questions

## Built and validated for

- **Claude** — [Anthropic](https://github.com/anthropics)
- **Codex** — [OpenAI](https://github.com/openai)
- **Copilot** — [GitHub](https://github.com/github)
- **Cursor** — [Anysphere](https://github.com/cursor)
- **Gemini** — [Google](https://github.com/google-gemini)

## License

[BUSL 1.1](LICENSE) - converts to Apache 2.0 three years after each release.
