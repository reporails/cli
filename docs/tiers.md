---
title: "Tiers and Limits"
description: "Free vs Pro — what each tier includes"
version: "0.6.0"
last_updated: 2026-09-20
---

# Tiers and Limits

Reporails has two tiers: **Free** and **Pro**.

- **Free** is every user without an active Pro subscription — whether you are anonymous (no account) or signed in with a free account. Both share identical limits and identical diagnostic detail: the score, every local finding with its line, per-file counts for the interaction findings, and the local deterministic fixes. Signing in does not raise your limits; it gives you an account (for managing your subscription, and it enables `ails check --heal`) and changes the call-to-action from "sign in" to "upgrade".
- **Pro** is an active paid subscription. It raises the request rate and payload cap and unlocks the full per-finding remedy set and the ordered remediation workflow. The server sends no remedy text to an anonymous or free caller at all — Free's fixes are limited to what runs locally and needs no server round-trip.

The CLI sends your API key (if you have one) with each request; the diagnostic backend resolves your tier from your subscription state and applies the corresponding limits.

## Side by side

| Limit / capability                        | Free (anonymous or signed in) | Pro                                       |
|-------------------------------------------|-------------------------------|-------------------------------------------|
| Account                                   | Optional (`ails auth login`)  | Subscription via your account page        |
| Hourly request rate                       | 5 / hour                      | 1,200 / hour                              |
| Per-request payload cap                   | 2 MB                          | 20 MB                                     |
| Mechanical and structural rule findings   | Full detail                   | Full detail                               |
| Per-finding rule body and pass / fail     | Full detail                   | Full detail                               |
| Overall score and per-surface scores      | Full detail                   | Full detail                               |
| Per-finding fix text                      | None from the server — only the local deterministic fixes (e.g. wrapping a bare name in backticks) | Full per-finding remedy set               |
| Ranking findings by impact                | — (findings listed without a grade) | Yes — findings carry an impact grade; inline-formatting findings (backticks, bold, italics) are listed without one |
| Remediation workflow                      | —                             | Ordered, step-by-step fix plan            |
| Cross-file / interaction findings         | Which files + counts          | Full detail (file, line, what to change)  |
| Apply fixes (`ails check --heal`)         | Account required — anonymous gets the diagnosis, no writes | Yes            |

Free gives you the diagnosis: the score, every local finding with its line, per-file counts for the interaction findings, with the local deterministic fixes a check can make without a server round-trip. Pro adds the full per-finding remedy set and the composable remediation workflow — the ordered procedure your coding agent runs to fix the files.

On either tier the fix text (and, on Pro, the workflow) reaches your coding agent through the MCP `validate` tool and appears per finding in `ails check -f json`. The terminal output lists findings, not fixes.

## What the limits mean in practice

**Hourly request rate.** Each `ails check` run counts as one request. The free limit covers casual use — five runs per hour is enough to iterate while editing a single file. Once you cross the limit, the response is a `429 rate_limit_exceeded` with a call-to-action: anonymous is pointed at `ails auth login` and then at Pro (the account is the step before subscribing); a signed-in free user is pointed straight at upgrading to Pro.

After a `429`, the CLI waits for your limit to reset before contacting the server again: every run in the meantime shows the same limit message, with the "Try again in ~N min" countdown. This keeps watchers, hooks, and agent loops that re-run `ails check` from hammering a limit that is already spent. Signing in with `ails auth login` applies your account's limit straight away.

**Per-request payload cap.** The cap is the size of the analysis payload sent to the diagnostic backend (embeddings, structural metadata, file paths) — not the size of your instruction files on disk. A typical project sends well under 1 MB. Multi-MB payloads usually mean a very large root instruction file that should be split — see [FAQ → polyglot monorepo](faq.md#i-run-a-polyglot-monorepo-should-i-have-one-claudemd-or-many).

**Diagnostic detail.** The mechanical and structural checks return full detail on both tiers, including the finding's line. The difference is the *fix* depth and *cross-file* detail: Free gets no server fix text (only the local deterministic fixes), and shows which files a cross-file repetition or topic overlap touches and how many, not the lines; Pro adds the per-finding fix, the ordered remediation workflow, and the exact line each cross-file finding names.

Free output shows the score, a card per file with its first findings, a count of the rest and a one-line tally of their kinds (`-v` lists every finding with its line), a marketing line in place of any server fix text, and a separate cross-file section that counts the repetitions and topic overlaps per pair of files, without their lines:

```
  ┌─ Main (1)  6 directive / 1 constraint · 30% prose
  │ CLAUDE.md  6 dir / 1 con · 30% prose
  │   ✗       Unresolved imports: docs/setup.md  CORE:S:0024
  │   ⚠       Missing directory layout — show the project structure with a tre…  CORE:C:0035
  │     ... and 19 more
  │     6 vague · 7 brief · 1 weak
  │     ⊕ 2 Pro diagnostics — topic overlap, unbalanced topics
  │
  └─ 35 findings

  ── Cross-file ────────────────────────────────────────

  ⚠  .claude/rules/testing.md ↔ CLAUDE.md — 3 overlaps
  ⚠  .claude/rules/testing.md ↔ CLAUDE.md — 1 repetition

  Line-level detail → sign in with ails auth login, then upgrade to Pro

  ...
  Pro adds fix text and the order to apply it for the findings above.
  → sign in with ails auth login, then upgrade to Pro
```

Pro output folds a topic-overlap finding back into the per-file list with its line and its full message (`-v` shown here to avoid truncation); a cross-file *repetition* stays a summary count on both tiers — only the JSON `cross_file[]` carries its two lines. The per-finding fix and the ordered remediation workflow go to your coding agent through the MCP `validate` tool (`-f json` carries them too); the terminal output lists findings, not fixes:

```
  ┌─ Main (1)  2 directive / 2 constraint · 33% prose
  │ CLAUDE.md  2 dir / 2 con · 33% prose
  │   ⚠       Not a git repository  CORE:G:0001
  │     L5    57% of the instructions in this file and `.claude/rules/git.md`
  │           cover the same topics, and `.claude/rules/git.md` loads alongside
  │           this file whenever work touches its paths — keep each instruction
  │           in one file so copies can't drift apart.  CORE:C:0044
  │
  └─ 26 findings
  ...
  Fixes are in the JSON output (--format json) and the MCP tools.
```

A finding about a single instruction inside one file — a vague, weak or too-brief instruction, say — renders with its line on both tiers; the interaction and cross-file findings are where the tiers differ, as above.

When you cross an hourly limit, the normal output is replaced at the bottom of `ails check` with the assessment-box CTA. Anonymous is pointed at signing in first (the account is the prerequisite for subscribing) and then at Pro, which is what actually raises the cap; a signed-in free user is pointed straight at upgrading to Pro; Pro is pointed at the contact form so we can see the use case and raise the cap:

```
  ⚠  Server diagnostics unavailable.
  Anonymous limit hit (5/hr). Try again in ~12 min. Sign in with `ails auth login`, then upgrade to Pro to raise it to 1,200/hr
  Did you see an error? Let us know: https://github.com/reporails/cli/issues
```

```
  ⚠  Server diagnostics unavailable.
  Hit the free limit (5/hr). Try again in ~12 min. Upgrade to Pro to raise it to 1,200/hr
  Did you see an error? Let us know: https://github.com/reporails/cli/issues
```

The same shape renders for `payload_too_large` and `atom_cap_exceeded`.

## How to sign in

```bash
ails auth login        # GitHub Device Flow — authorize in browser, exchange for API key
ails auth status       # show whether you're signed in, the key source, and a redacted key prefix (the tier for a stored sign-in; a key from the environment shows "resolved at check time")
ails auth token        # print the full API key (for CI export)
ails auth logout       # remove stored credentials
```

`ails auth login` opens GitHub in your browser via the standard Device Flow; once you authorize, you have a free account. Credentials are stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX; Windows logs a warning that NTFS ACLs are not auto-restricted, so secure the file manually if you're on Windows).

For CI, capture the key and set it as a secret:

```bash
ails auth token   # prints the key to stdout
```

Then add it to your CI provider's secret store and pass it as `AILS_API_KEY` (env) or via the GitHub Action's `api-key` input — see [Configuration → Authentication](configuration.md#authentication).

## Why sign in, and why upgrade?

You can run `ails check` anonymously with no setup — the score, every local finding with its line, and per-file counts for the interaction findings are free, forever. Signing in with a free account keeps your usage under your identity, enables `ails check --heal`, and is the step before subscribing; it does not raise any limit or add server fix text. Upgrading to Pro raises the request rate and payload cap and unlocks the full per-finding remedy set plus the ordered remediation workflow — the fixes your coding agent applies end to end.

---

[← Agent Support](agent-support.md) · Tiers and Limits · [Configuration →](configuration.md)
