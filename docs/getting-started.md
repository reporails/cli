---
title: "Getting Started"
description: "Install, first run, what the output means"
version: "0.6.0"
last_updated: 2026-09-20
---

# Getting Started

## Quick start

From the root of any repository that has at least one instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, or `GEMINI.md`) — no install, no account:

```bash
npx @reporails/cli check
# or
uvx --from reporails-cli ails check
```

> **First run downloads the model once (~275 MB).** The package itself is small; on the first `check` that needs it, Reporails downloads its analysis model into `~/.reporails/cache/` and prints a `Downloading reporails model…` banner followed by one line per file fetched. The download lives in your home cache, not the package cache, so it happens once per machine and every later run — including a fresh `npx` — is silent and offline. A first run needs network access; see [Configuration](configuration.md#model-cache) to point the download at a mirror. A CI job starts on a fresh machine every time; see [Caching the model in CI](configuration.md#caching-the-model-in-ci) so that only the first run downloads it.

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

  Quality   7.9 / 10  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░  (1.3s)
  Fix now   16 errors. Start with CORE:C:0053.
  Findings  21 total · -v to list every one
  Agent: Claude
  Level: L4 Delegated

  Scope:
    instructions: 4 directive / 7 prose (50%)
                  3 constraint
```

Three things to read first:

- **Quality** — closer to 10 is better. See the [Score Guide](score-guide.md) for what each band means.
- **Fix now** — the error count and the rule to start with. The `Findings` total beneath it is the size of the rest.
- **Findings list** — each row is a rule that fired. Run `ails explain CORE:C:0035` (or whichever rule ID) to see what the rule checks for and how to fix it. In supporting terminals the rule IDs in the output are clickable links to their docs page.
- **Scope summary** — counts of directives, constraints, and prose detected. If a number looks wrong (e.g., zero directives), your instructions are probably written as prose rather than as commands the agent can act on.

Reporails ships in two pieces: the **engine** (the CLI + MCP server) and the **plugin** (the `ails` skill + MCP registration your agent installs natively).

**1. Install the engine on your PATH:**

```bash
uv tool install reporails-cli
# or
npm install -g @reporails/cli
```

`ails install` then ensures the binary is on PATH. After it runs, `ails check` works from anywhere without the `npx` / `uvx` prefix.

**2. Add the reporails plugin to your agent.** The plugin carries the `ails` skill and the MCP server; installing it registers both in one step — no per-agent config editing. The per-agent install commands are listed in [Agent Support](agent-support.md#plugin-support); `ails install` runs them for Claude Code and Codex and prints the rest. Add `--project` to install the plugin for the current repository only, shared with collaborators (Codex installs for your user); `ails update` refreshes the plugin in each agent that has it. What the plugin needs to start is stated there. Without the plugin, `ails check` in your terminal scores your instruction files and applies formatting fixes; rewriting them needs the plugin and Pro (`/reporails:ails heal` in Claude Code).

## Configure (optional)

Reporails auto-detects which agent rules to run based on the base config files present in your repo, so most projects need no setup. You may want to pin a default if your repo has multiple agents (`CLAUDE.md` + `.cursorrules` + `AGENTS.md`) and you want to bias toward one of them:

```bash
ails config set --global default_agent claude
```

Per-repo settings, rule thresholds, and rule disables live in `.ails/config.yml` — see [Configuration](configuration.md) for the full surface.

## Authenticate (optional, free)

The anonymous tier works without an account and is enough to see whether your instructions are working — the full diagnosis, every finding, and the score. Signing in is free and does not change your rate or payload caps — anonymous and signed-in free accounts share the same limits. What an account gives you is an identity (so you can subscribe and manage the subscription) and `ails check --heal`, which refuses to write files for an anonymous run. Raising the caps and unlocking the full diagnostic detail (the remedies, and the exact line of each cross-file repetition and topic overlap) is what Pro adds:

```bash
ails auth login    # browser-based GitHub Device Flow
ails auth status   # show whether you are signed in, the key source and a redacted key prefix (the tier for a stored sign-in; a key from the environment shows "resolved at check time")
ails auth token    # print the full API key (for CI export)
ails auth logout   # remove stored credentials
```

See [Tiers and Limits](tiers.md) for the side-by-side breakdown, and [Configuration → Authentication](configuration.md#authentication) for the credential-storage and CI specifics.

## Common follow-ups

- **The score is lower than you expected.** Run `ails check -v` to see all findings (the default output may leave some out). Then `ails explain CORE:S:0002` (or whichever rule ID) to see the rule body and pass / fail examples. The [Score Guide](score-guide.md) explains what each band means, how per-surface scores roll up, and which rules to start with.
- **You disagree with a rule.** Browse [reporails.com/rules](https://reporails.com/rules) for the rule's intent before deciding, then disable it in `.ails/config.yml` — see [Configuration → Disabling rules](configuration.md#disabling-rules).
- **You want this in CI.** See the [GitHub Actions section in the README](https://github.com/reporails/cli#readme) and [Configuration → Authentication](configuration.md#authentication) for capturing your API key with `ails auth token` and wiring it as `secrets.REPORAILS_API_KEY`.

## Useful flags

```bash
ails check -v               # verbose — show all findings, not just top per file
ails check -f json          # machine-readable JSON
ails check -f github        # GitHub Actions inline annotations
                            # (text, json and github are the only formats; any
                            #  other value is a usage error)
ails check --strict              # exit code 1 if any finding fires
ails check --agent claude        # only run rules scoped to one agent
ails check CLAUDE.md --heal      # apply deterministic auto-fixes to one target (needs an account)
ails check CLAUDE.md --fix       # alias for --heal (eslint / ruff convention)
ails check CLAUDE.md --heal --dry-run  # preview fixes without writing (needs an account)
ails check --heal --cwd          # with --heal: opt into rewriting the whole project instead of naming a target
```

`--heal` needs an explicit target — a path or a capability like `skills` — or `--cwd` to opt into rewriting the whole project; a bare `ails check --heal` exits with an error naming both options. It also needs an account: run `ails auth login` first — a free account is enough, and Pro is not required. Without stored credentials (or an `AILS_API_KEY` in the environment) the run still prints the full diagnosis, then declines the fix pass with `Applying fixes needs an account.` and applies nothing. See [Tiers and Limits](tiers.md).

The JSON output groups findings under `files{path: {findings: [...], count: N}}` plus aggregate `stats` and (when present) `cross_file` blocks — see [Configuration → Output format](configuration.md#output-format) for the full shape, including which fields are tier-conditional.

## Focus on one file or capability

When the whole-repo view is too noisy, name the target. Each positional is `capability:name`, `@capability` (all of capability), or a path:

```bash
ails check skills:backlog    # focus on .claude/skills/backlog/SKILL.md
ails check rules:git         # focus on .claude/rules/git.md
ails check agents:rule-writer
                             # subagent + any skills its frontmatter preloads
ails check @skills           # listing mode — every skill, one card each
ails check ./CLAUDE.md       # focus on a path
ails check .claude/skills    # focus on a directory — every instruction file under it
ails check skills:backlog @agents  # mix: one skill + all agents
```

Only the named files are read and checked, so cross-file rules compare them with each other, not with the rest of the project, and checks about the project as a whole (such as whether a main instruction file exists) are skipped. The output uses the same per-file card layout as a whole-project run, narrowed to the named target. Listing mode (`ails check <capability>` with no name) narrows the same card layout to every file under that capability instead of a single one. Capability names come from the agent's declared `file_types:` — both singular and plural are accepted.

The whole-repo summary also shows a `Top rules (by finding count)` block — a fast triage view of which rule classes contribute the most findings across your project.

## Next steps

- [Score Guide](score-guide.md) — what the number means in practice
- [Tiers and Limits](tiers.md) — Free vs Pro, what each tier includes
- [Configuration](configuration.md) — tuning rules, agents, exclusions
- [FAQ](faq.md) — common questions

---

[← Reporails CLI Documentation](index.md) · Getting Started · [Agent Support →](agent-support.md)
