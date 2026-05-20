---
title: "Getting Started"
description: "Install, first run, what the output means"
version: "0.5.11"
last_updated: 2026-05-20
---

# Getting Started

## Quick start

From the root of any repository that has at least one instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, or `GEMINI.md`) — no install, no account:

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

You'll see something like this:

```
Reporails — Diagnostics

  ┌─ Main (1)  4 directive / 3 constraint · 50% prose
  │ CLAUDE.md  4 dir / 3 con · 50% prose
  │   ⚠ L9    Missing directory layout — show the project structure  CORE:C:0035
  │   ⚠ L23   7 of 7 instruction(s) lack effective reinforcement  CORE:C:0053
  │     ... and 19 more
  │     1 misordered · 1 orphan · 1 ambiguous
  │
  └─ 21 findings

  ── Summary ────────────────────────────────────────────────────────

  Score: 7.9 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░  (1.3s)
  Agent: Claude

  Scope:
    instructions: 4 directive / 7 prose (50%)
                  3 constraint

  21 findings · 4 warnings · 1 info
```

Three things to read first:

- **Score** — closer to 10 is better. See the [Score Guide](score-guide.md) for what each band means.
- **Findings list** — each row is a rule that fired. Run `ails explain CORE:C:0035` (or whichever rule ID) to see what the rule checks for and how to fix it.
- **Scope summary** — counts of directives, constraints, and prose detected. If a number looks wrong (e.g., zero directives), your instructions are probably written as prose rather than as commands the agent can act on.

## Install permanently

```bash
npx @reporails/cli install
# or
uvx --from reporails-cli ails install
```

Either command does two things:

1. Puts the `ails` binary on your PATH
2. Writes a one-line `~/.reporails/config.yml` with sensible defaults

After this, `ails check` runs from anywhere without the `npx` / `uvx` prefix.

## Configure (optional)

Reporails auto-detects which agent rules to run based on the base config files present in your repo, so most projects need no setup. You may want to pin a default if your repo has multiple agents (`CLAUDE.md` + `.cursorrules` + `AGENTS.md`) and you want to bias toward one of them:

```bash
ails config set --global default_agent claude
```

Per-repo overrides, severity tweaks, and rule disables live in `.ails/config.yml` — see [Configuration](configuration.md) for the full surface.

## Authenticate (optional, for full diagnostics)

The anonymous tier works without an account and is enough to see whether your instructions are working. Sign in to raise your request and payload caps and unlock the full diagnostic detail (per-finding fix text and exact cross-file conflict locations):

```bash
ails auth login    # browser-based GitHub Device Flow
ails auth status   # show current tier and a redacted key prefix
ails auth token    # print the full API key (for CI export)
ails auth logout   # remove stored credentials
```

See [Tiers and Limits](tiers.md) for the side-by-side breakdown, and [Configuration → Authentication](configuration.md#authentication) for the credential-storage and CI specifics.

## Common follow-ups

- **The score is lower than you expected.** Run `ails check -v` to see all findings (the default output truncates after a per-file budget). Then `ails explain CORE:S:0001` (or whichever rule ID) to see the rule body and pass / fail examples. The [Score Guide](score-guide.md) explains what each band means, how per-surface scores roll up, and which rules to fix first for the biggest score improvement.
- **You disagree with a rule.** Browse [reporails.com/rules](https://reporails.com/rules) for the rule's intent before deciding, then either disable it or override its severity in `.ails/config.yml` — see [Configuration → Disabling rules](configuration.md#disabling-rules).
- **You want this in CI.** See the [GitHub Actions section in the README](https://github.com/reporails/cli#readme) and [Configuration → Authentication](configuration.md#authentication) for capturing your API key with `ails auth token` and wiring it as `secrets.REPORAILS_API_KEY`.

## Useful flags

```bash
ails check -v               # verbose — show all findings, not just top per file
ails check -f json          # machine-readable JSON
ails check -f github        # GitHub Actions inline annotations
ails check --strict         # exit code 1 if any finding fires
ails check --agent claude   # only run rules scoped to one agent
```

The JSON output groups findings under `files{path: {findings: [...], count: N}}` plus aggregate `stats` and (when present) `cross_file` blocks — see [Configuration → Output format](configuration.md#output-format) for the full shape, including which fields are tier-conditional.

## Focus on one file or capability

When the whole-repo view is too noisy, name the target. Each positional is `capability:name`, `@capability` (all of capability), or a path:

```bash
ails check skills:backlog    # focus on .claude/skills/backlog/SKILL.md
ails check rules:git         # focus on .claude/rules/git.md
ails check agents:rule-writer
                             # subagent + any skills its frontmatter preloads
ails check @skills           # listing mode — table of all skills with scores
ails check ./CLAUDE.md       # focus on a path
ails check skills:backlog @agents  # mix: one skill + all agents
```

The full pipeline still runs (so cross-file rules see the whole project), but only the focused file or capability appears in the output, with findings grouped by rule and a `Next:` action pointer. Listing mode (`ails check <capability>` with no name) prints a per-target score table for that capability under the detected agent. Capability names come from the agent's declared `file_types:` — both singular and plural are accepted.

The whole-repo summary also shows a `Top rules (by finding count)` block — a fast triage view of which rule classes contribute the most findings across your project.

## Next steps

- [Score Guide](score-guide.md) — what the number means in practice
- [Tiers and Limits](tiers.md) — anonymous vs signed-in mode, what each includes
- [Configuration](configuration.md) — tuning rules, agents, exclusions
- [FAQ](faq.md) — common questions

---

[← Reporails CLI Documentation](index.md) · Getting Started · [Agent Support →](agent-support.md)
