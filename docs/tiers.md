---
title: "Tiers and Limits"
description: "Anonymous vs signed in, what each mode includes"
version: "0.5.11"
last_updated: 2026-06-06
---

# Tiers and Limits

Reporails has two access modes: **anonymous** (no account, no setup) and **signed in** (free, GitHub Device Flow). The CLI auto-detects which mode you're in based on whether `ails auth login` has been run, and the diagnostic backend applies the corresponding limits.

## Side by side

| Limit / capability                        | Anonymous       | Signed in                                |
|-------------------------------------------|-----------------|------------------------------------------|
| Account                                   | Not required    | Free, `ails auth login`                  |
| Hourly request rate                       | 5 / hour        | 200 / hour                               |
| Per-request payload cap                   | 2 MB            | 20 MB                                    |
| Mechanical and structural rule findings   | Full detail     | Full detail                              |
| Per-finding rule body and pass / fail     | Full detail     | Full detail                              |
| Overall score and per-surface scores      | Full detail     | Full detail                              |
| Per-finding fix text                      | Summary only    | Full detail                              |
| Cross-file conflict detection             | Counts per file | Full detail (file, line, what to change) |
| Cross-file repetition detection           | Counts per file | Full detail                              |

## What the limits mean in practice

**Hourly request rate.** Each `ails check` run counts as one request. The anonymous limit covers casual use — five runs per hour is enough to iterate while editing a single file. Once you cross the limit, the response is a `429 rate_limit_exceeded` with a CTA pointing at sign-in.

**Per-request payload cap.** The cap is the size of the analysis payload sent to the diagnostic backend (embeddings, structural metadata, file paths) — not the size of your instruction files on disk. A typical project sends well under 1 MB. Multi-MB payloads usually mean a very large root instruction file that should be split — see [FAQ → polyglot monorepo](faq.md#i-run-a-polyglot-monorepo-should-i-have-one-claudemd-or-many).

**Diagnostic detail.** The mechanical and structural checks return full detail in both modes. The difference is in *interaction* and *cross-file* findings: anonymous gets counts per file, signed-in gets the file, the line, and the suggested fix.

Anonymous output shows the score, per-file counts, and a separate cross-file section that only counts the conflicts and repetitions per pair of files:

```
  ┌─ Main (1)
  │ CLAUDE.md  10 dir / 1 con / 1 amb · 71% prose
  │   ⚠       Missing tech stack declaration  CORE:C:0034
  │   ⚠       Missing MCP documentation  CORE:C:0027
  │     4 brief · 1 orphan
  │
  └─ 21 findings

  ── Cross-file ───────────────────────────────────────────

  ⚠  CLAUDE.md ↔ .claude/rules/git.md     — 2 conflicts
  ⚠  CLAUDE.md ↔ .claude/rules/python.md  — 1 repetition

  Line-level detail and fixes → ails auth login
```

Signed-in output folds cross-file findings back into the per-file list with the line, the message, and the suggested fix — so the cross-file section above is replaced by inline findings in each file:

```
  ┌─ Main (1)
  │ CLAUDE.md  10 dir / 1 con / 1 amb · 71% prose
  │   ⚠ L18    Conflicting commit-message format with .claude/rules/git.md:5
  │            Reconcile to a single source — keep one canonical directive.
  │   ⚠ L42    Repeated test-runner directive (also in .claude/rules/python.md:8)
  │            Move the shared directive to .claude/rules/ and remove the root duplicate.
  │   ⚠       Missing tech stack declaration — list languages, frameworks, and runtimes  CORE:C:0034
  │            Add: "Python 3.12, FastAPI, pytest" near the top of CLAUDE.md.
  │   ⚠       Missing MCP documentation — describe MCP server configuration if applicable  CORE:C:0027
  │            Add a "## MCP servers" section listing each server, transport, and trigger.
  │     4 brief · 1 orphan
  │
  └─ 23 findings
```

Within-file conflicts (one section in `CLAUDE.md` contradicting another section in the same file) render as regular findings in both modes — they're not separated out the way cross-file ones are.

When you cross an hourly limit, the normal output is replaced at the bottom of `ails check` with the assessment-box CTA. Anonymous mode points at the next-step command, signed-in modes point at GitHub issues so we can see your use case and raise the cap:

```
  ⚠  Server diagnostics unavailable.
  Anonymous limit hit (5/hr). Run `ails auth login` to raise it 5x
  Did you see an error? Let us know: https://github.com/reporails/cli/issues
```

```
  ⚠  Server diagnostics unavailable.
  Hit your hourly limit (200/hr) — file an issue with your use case so we can raise it
  Did you see an error? Let us know: https://github.com/reporails/cli/issues
```

The same shape renders for `payload_too_large` and `atom_cap_exceeded`.

## How to sign in

```bash
ails auth login        # GitHub Device Flow — authorize in browser, exchange for API key
ails auth status       # show your current tier and a redacted key prefix
ails auth token        # print the full API key (for CI export)
ails auth logout       # remove stored credentials
```

`ails auth login` opens GitHub in your browser via the standard Device Flow; once you authorize, you're signed in. Credentials are stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX; Windows logs a warning that NTFS ACLs are not auto-restricted, so secure the file manually if you're on Windows).

For CI, capture the key and set it as a secret:

```bash
ails auth token   # prints the key to stdout
```

Then add it to your CI provider's secret store and pass it as `AILS_API_KEY` (env) or via the GitHub Action's `api-key` input — see [Configuration → Authentication](configuration.md#authentication).

## Why two modes?

Anonymous mode exists so anyone can run `ails check` once or twice without setting anything up — useful for trying the tool. Signed-in mode exists for everyday use, where you want larger payloads, higher request rates, and the full per-finding detail.

---

[← Agent Support](agent-support.md) · Tiers and Limits · [Configuration →](configuration.md)
