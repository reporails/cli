---
title: "FAQ"
description: "Common questions"
version: "0.6.1"
last_updated: 2026-09-20
---

# FAQ

## Why is my score lower than I expected?

The score is a single quality verdict, **not a tally of findings**. It measures how strongly your instructions are written — how specific, direct, and well-structured they are, and how little they compete with one another — so a file with vague, buried, or competing instructions scores low even when the finding *count* is small, and a long file with many low-effect findings can still score well. The `Findings` line is a separate worklist; clearing low-severity findings will not move the number much.

To see what's pulling it down, run `ails check -v` and read the per-surface bars (Main, Rules, Skills, …) — the lowest-scoring surface is where the weak instructions live. See [Score Guide](score-guide.md) for how the number is built.

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

Signing in is free, and it does not change your limits: an anonymous run and a signed-in free run share the same hourly rate and per-request payload cap. What an account gives you is an identity — you can subscribe, manage the subscription, and use `ails check --heal`, which declines to write files for an anonymous run.

Anonymous and free already show *what's* wrong and *where*: every local finding with its line, and the file-level findings as per-file counts where the line detail belongs to Pro. The deeper diagnostic is what **Pro** adds: the *remedies* (what to change, where, and how), the *exact line* of every cross-file repetition and topic overlap (anonymous and free see which files and how many, not the lines), and the ordered remediation workflow your coding agent runs end to end. The server sends no remedies at all to anonymous or free callers — only the deterministic, local fixes (like wrapping a bare name in backticks) ship free, because those run entirely on your machine. Pro also raises the hourly rate (5 → 1,200) and the payload cap (2 MB → 20 MB).

Sign in with `ails login`: it prints a link and a short code, opens your browser when it can, and finishes when you approve. The link is valid for 30 seconds; when it runs out, run `ails login` again. You sign in once per machine, and it lasts a year. The sign-in is stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX); `ails logout` signs out only that machine. Your plan comes from your account, so any machine you sign in on gets it. For CI, create an API key on [reporails.com/account](https://reporails.com/account).

Full breakdown of what each mode includes: [Tiers and Limits](tiers.md).

## I signed out (or lost my key). How do I get Pro back on this machine?

Run `ails login`. Your plan comes from your account, so signing in gives this machine your plan with no key to copy.

## How do I sign in on a server over SSH?

Run `ails login`. Over SSH without a forwarded display it prints the link and a short code instead of opening a browser; open the link on your own machine within 30 seconds, check the code matches the page, and approve. The command on the server then finishes. With X forwarding, the page opens on your screen.

## My CI stopped authenticating after upgrading to 0.6.1

The token command from 0.6.0 no longer exists. Create an API key on [reporails.com/account](https://reporails.com/account) and set it as the CI secret: `AILS_API_KEY` in the environment, or the `api-key` input of the GitHub Action. An API key and a sign-in on the same account share one plan and one hourly limit.

## What are the messages above my results?

They are messages about your account: a failed payment (Pro stays on while the card is retried), Pro ending on a date, Pro having ended, or an announcement. A warning shows on every run; other messages show once a day. `ails check -f json` and the MCP `validate` reply carry all of them in a `notices` list, and `--format github` (the GitHub Action) prints each one as a workflow annotation. See [Tiers and Limits](tiers.md#messages-about-your-account).

## Does Reporails read my source code?

No. The CLI reads only the instruction-file types listed in [Agent Support](agent-support.md) — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, `GEMINI.md`, plus the rule / skill / agent / hook files associated with each. It does not scan your repo's `src/`, `tests/`, or any other application code.

See the [privacy notice](https://reporails.com/privacy-policy).

## Can I use this offline?

The local rules (mechanical and structural) run fully offline. The semantic rules (reinforcement patterns, content-quality checks, cross-file analysis) require a request to the diagnostic backend. There is no offline-only mode for those, the analysis and diagnostics runs server-side.

When the analysis backend is unreachable, the run degrades gracefully: the headline reads `Quality n/a` and the per-surface and per-item score bars are suppressed (there's no single quality score without the analysis service). You still get the findings from the local rules, the scope summary, and the local (mechanical and structural) rule results — just no score.

## Is my instruction file ever stored on the diagnostic backend?

No. The text of your instructions stays on your machine. The Reporails backend receives analysis metadata only: no sentence or paragraph of your text is sent, and the only words of it that travel are marker words from a short fixed list (such as `never`, `must` or `use`) that sit inside some sentences.

See the [privacy notice](https://reporails.com/privacy-policy).

## I run a polyglot monorepo. Should I have one `CLAUDE.md` or many?

Different agents handle this differently — see [Agent Support](agent-support.md) for the per-agent layout. For Claude, use one root `CLAUDE.md` for project-wide identity and constraints, and per-directory child `CLAUDE.md` files for path-specific guidance — Claude Code loads them automatically when you cd into the directory. For Cursor, use `.cursor/rules/*.mdc` for per-directory guidance. Codex reads `AGENTS.md` in each directory from the root down; Antigravity reads `AGENTS.md`, `GEMINI.md` and `.agents/rules/` in any subdirectory.

If you only have a root file but a large repo, you'll likely trip `CORE:E:0002` (Instruction File Size Limit) and / or `CORE:E:0001` (Total Instruction Size Limit). Split the content into the agent's native child-file mechanism, listed per-agent on [Agent Support](agent-support.md).

## Why does my CI run say "anonymous" even though I'm authenticated locally?

CI runs in a fresh environment without the credentials file at `~/.reporails/credentials.yml` that `ails login` writes locally. Create an API key on [reporails.com/account](https://reporails.com/account), store it as a secret in your CI provider, and pass it via the action input or environment variable:

```yaml
- uses: reporails/cli/action@0.6.1
  with:
    api-key: ${{ secrets.REPORAILS_API_KEY }}
```

See the [GitHub Actions section in the README](https://github.com/reporails/cli#readme).

## Does every CI run download the model again?

No, as long as the model is cached. A CI job starts on a fresh machine, so without a cache each run downloads the ~275 MB model again. The `reporails/cli/action` GitHub Action caches it for you: the first run downloads it, and later runs restore it from the repository's Actions cache, even when the check fails. If you run `ails` directly in a workflow, add the cache step from [Configuration → Caching the model in CI](configuration.md#caching-the-model-in-ci). That section also lists the few cases where a cached setup still downloads once, such as the first run after a CLI update that brings a new model.

## Is the rule set the same for every agent?

No. Reporails ships **CORE rules** that are agent-neutral (file size, heading hierarchy, reinforcement patterns, credential handling, cross-file consistency) and **per-agent rules** that target each agent's own config formats (Claude hooks, Cursor `.mdc` rule frontmatter, Copilot instructions, Codex AGENTS.md conventions, Antigravity commands and extensions). See [Agent Support → Cross-agent rules](agent-support.md#cross-agent-rules) for the breakdown of which rules fire universally.

When you run `ails check --agent claude`, only CORE plus Claude-scoped rules fire. Without `--agent`, Reporails [auto-detects which agents are present](agent-support.md#how-agent-detection-works) by looking for each agent's base config file and runs the corresponding rule sets.

## How do I auto-fix findings?

Run `ails check <target> --heal` (a path, or a capability like `skills`) — it applies the deterministic formatting fixes after validation and lists any missing sections for you to write. `--heal` needs an explicit target or `--cwd` to opt into rewriting the whole project; a bare `ails check --heal` exits with an error naming both options. Healing also needs an account: run `ails login` first (a free account is enough — Pro is not required). An anonymous run still prints the full diagnosis, then declines the fix pass with `Applying fixes needs an account.` and changes nothing. Preview what would change with `ails check <target> --heal --dry-run`. `--fix` is an alias for `--heal` (matching the eslint / ruff convention), so `ails check <target> --fix` works the same way. To have your agent rewrite the instruction files (Pro), run `ails install`, then `/reporails:ails heal` in Claude Code; in other agents, ask your agent to run the reporails heal. See [Tiers and Limits](tiers.md).

## What's the right way to file a bug?

Open an issue at [github.com/reporails/cli/issues](https://github.com/reporails/cli/issues). Include the version (`ails version`), your OS / Python version, the command you ran, and the unexpected output. JSON output (`ails check -f json`) is the most useful format for bug reports.

---

[← Capability Levels](capability-levels.md) · FAQ
