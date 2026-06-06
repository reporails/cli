---
title: "FAQ"
description: "Common questions"
version: "0.5.11"
last_updated: 2026-05-20
---

# FAQ

## Why is my score lower than I expected?

The score reflects severity-weighted findings, not finding *count*. One critical finding will pull the score down further than five low-severity ones. Run `ails check -v` to see all findings, then look at the top of the list — if there's a `critical` or `high` row, that's the score driver.

If you disagree with a specific finding, [open an issue](https://github.com/reporails/cli/issues) so we can review the rule, and / or disable the rule locally — see [How do I disable a rule I disagree with?](#how-do-i-disable-a-rule-i-disagree-with) below.

## How do I make an agent write rule-compliant skills on the first try?

Use `ails rules list --capability=skill -f md` to fetch the workflow-ordered rule set, then paste it into the agent's authoring prompt. The agent reads the constraints first and writes a compliant SKILL.md instead of patching findings after `ails check`. Same flow for `--capability=agent`, `--capability=rule`, `--capability=main`. `--no-examples` strips Pass/Fail blocks for a shorter context payload. See [Rules CLI](rules-cli.md).

## How do I disable a rule I disagree with?

Add it to `.ails/config.yml`:

```yaml
disabled_rules:
  - CORE:C:0010   # Build And Test Commands
```

Run `ails explain CORE:C:0010` first to read the rule body and pass / fail examples. Understand what the rule is checking before you decide whether to comply with it. Disabling is the right call when the rule's intent doesn't fit your project. Complying is the right call when the intent matches your project, but you weren't reaching it before.

## What changes when I sign in?

Anonymous mode is enough to see *what's* wrong and *how many* cross-file conflicts exist. Signing in gives you the full diagnostic: the *exact line* each finding refers to, the *fix text* the rule recommends, and the *coordinates* of every cross-file conflict — what to change to satisfy the rule, not just that something is off. Signing in also raises the per-request payload cap and hourly rate.

Sign in with `ails auth login` (browser-based GitHub Device Flow — the CLI exchanges your GitHub token for a Reporails API key). Credentials are stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX); remove them with `ails auth logout`. To capture the key for CI, run `ails auth token`.

Full breakdown of what each mode includes: [Tiers and Limits](tiers.md).

## Does Reporails read my source code?

No. The CLI reads only the instruction-file types listed in [Agent Support](agent-support.md) — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, `GEMINI.md`, plus the rule / skill / agent / hook files associated with each. It does not scan your repo's `src/`, `tests/`, or any other application code.

See [reporails.com/privacy-policy](https://reporails.com/privacy-policy) for the data-handling specifics on what is sent to the diagnostic backend, how long it is retained, and what is logged.

## Can I use this offline?

The local rules (mechanical and structural) run fully offline. The semantic rules (reinforcement patterns, content-quality checks, cross-file analysis) require a request to the diagnostic backend. There is no offline-only mode for those, the analysis and diagnostics runs server-side.

## Is my instruction file ever stored on the diagnostic backend?

No. Instruction file contents never leave your machine. The CLI parses your files locally and computes embeddings on-device; the diagnostic backend receives only analysis metadata (embeddings, structural counts, cluster IDs, file paths) — never the prose, examples, or reasoning text in your instruction files.

See [reporails.com/privacy-policy](https://reporails.com/privacy-policy) for the full data-handling specifics.

## I run a polyglot monorepo. Should I have one `CLAUDE.md` or many?

Different agents handle this differently — see [Agent Support](agent-support.md) for the per-agent layout. For Claude, use one root `CLAUDE.md` for project-wide identity and constraints, and per-directory child `CLAUDE.md` files for path-specific guidance — Claude Code loads them automatically when you cd into the directory. For Cursor, use `.cursor/rules/*.mdc` for per-directory guidance. Codex and Gemini read a single root file (`AGENTS.md` or `GEMINI.md`).

If you only have a root file but a large repo, you'll likely trip `CORE:E:0002` (Instruction File Size Limit) and / or `CORE:E:0001` (Total Instruction Size Limit). Split the content into the agent's native child-file mechanism, listed per-agent on [Agent Support](agent-support.md).

## Why does my CI run say "anonymous" even though I'm authenticated locally?

CI runs in a fresh environment without the credentials file at `~/.reporails/credentials.yml` that `ails auth login` writes locally. Capture your key with `ails auth token`, store it as a secret in your CI provider, and pass it via the action input or environment variable:

```yaml
- uses: reporails/cli/action
  with:
    api-key: ${{ secrets.REPORAILS_API_KEY }}
```

See the [GitHub Actions section in the README](https://github.com/reporails/cli#readme).

## Is the rule set the same for every agent?

No. Reporails ships **CORE rules** that are agent-neutral (file size, heading hierarchy, reinforcement patterns, credential handling, cross-file consistency) and **per-agent rules** that target each agent's own config formats (Claude hooks, Cursor `.mdc` rule frontmatter, Copilot instructions, Codex AGENTS.md conventions, Gemini commands and extensions). See [Agent Support → Cross-agent rules](agent-support.md#cross-agent-rules) for the breakdown of which rules fire universally.

When you run `ails check --agent claude`, only CORE plus Claude-scoped rules fire. Without `--agent`, Reporails [auto-detects which agents are present](agent-support.md#how-agent-detection-works) by looking for each agent's base config file and runs the corresponding rule sets.

## How do I auto-fix findings?

Run `ails check --heal` — it applies the deterministic fixes (missing sections, formatting) after validation. Preview what would change first with `ails check --heal --dry-run`.

## What's the right way to file a bug?

Open an issue at [github.com/reporails/cli/issues](https://github.com/reporails/cli/issues). Include the version (`ails version`), your OS / Python version, the command you ran, and the unexpected output. JSON output (`ails check -f json`) is the most useful format for bug reports.

---

[← Capability Levels](capability-levels.md) · FAQ
