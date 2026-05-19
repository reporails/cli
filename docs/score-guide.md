---
title: "Score Guide"
description: "How the score is built and what it tells you"
version: "0.5.6"
last_updated: 2026-05-04
---

# Score Guide

Every `ails check` run produces a single composite score between 0 and 10, plus per-surface scores for the parts of your instruction system that have content (Main / Rules / Skills / Agents / Memory). The number is meant to give you a quick read on whether your instructions are working before you dive into individual findings; both anonymous and signed-in modes return the score.

## How to read the number

The score is qualitative, not absolute:

| Range     | Read                                                                                                                |
|-----------|---------------------------------------------------------------------------------------------------------------------|
| 9.0 – 10  | Polished. Findings remaining are usually stylistic or low-severity.                                                 |
| 7.5 – 8.9 | Strong baseline. A handful of structural or coherence issues to address.                                            |
| 6.0 – 7.4 | Working but rough. Likely missing reinforcement, has size or scope issues, or contradicts itself somewhere.         |
| 4.0 – 5.9 | Weak. Several high-severity findings; the agent is probably ignoring or misinterpreting parts of your instructions. |
| Below 4.0 | The instruction file isn't doing what you think it is. Read the top findings carefully.                             |

These are guidance, not thresholds. A score of 6.5 with one critical finding can be much worse than a score of 7.5 with five low-severity ones — always look at the *top* of the findings list, not just the number.

## What contributes

The overall score reflects:

1. **Severity of findings that fired** — `critical`, `high`, `medium`, `low`, `info`. Higher severity weighs more.
2. **Coverage of the rule set** — rules that didn't fire (because the relevant content was clean) contribute positively.
3. **Per-surface health** — each instruction surface (Main / Rules / Skills / Agents / Memory) contributes its own score to the overall picture.

## Surface scores

The CLI reports a separate score for each instruction surface that has content in your repo:

```
Main (4):     ▓▓▓▓▓▓▓▓▓▓░░░░░   6.9    Rules (13):   ▓▓▓▓▓▓▓▓▓▓▓▓░░░   7.9
Skills (10):  ▓▓▓▓▓▓▓▓▓▓▓░░░░   7.2    Agents (3):   ▓▓▓▓▓▓▓▓▓▓░░░░░   6.9
```

Each surface is scored from the findings whose file falls in that surface (Main = root instruction files like `CLAUDE.md`, Rules = `.claude/rules/**/*.md` etc., Skills = `.claude/skills/**/SKILL.md` etc., Agents = `.claude/agents/**/*.md` etc., Memory = the auto-memory files for agents that have them). The number in parentheses is the file count contributing to that surface.

A common pattern: a strong Main score with a weak Rules score means you've written good top-level identity but your per-directory rules are missing reinforcement, contradicting the root, or oversized — drill into Rules findings first.

## How to read findings

Findings are sorted by severity, then by impact. The top entries are the ones to fix first. Each finding shows:

- **Rule ID** like `CORE:S:0001` — pass to `ails explain` for the rule body
- **Severity** — `critical`, `high`, `medium`, `low`, `info`
- **Location** — the file where the rule fired; line-level findings also show `L<n>` (e.g. `⚠ L9`), file-level findings show no line marker because the rule applies to the whole file
- **Message** — one-line description of what's wrong
- **Fix** — suggested change or pattern to apply

Anonymous runs show summary findings and cross-file conflict counts — enough to see whether your instructions are working. Sign in with `ails auth login` to unlock full per-finding fix text and the exact location of each cross-file conflict. See [Tiers and Limits](tiers.md) for the side-by-side breakdown of what each mode includes.

## Improving the score

The fastest improvements usually come from:

- **Add reinforcement.** If many findings cite `CORE:C:0053` (The Ideal Instruction), your directives are using softer language than the rule expects (e.g., "you should" instead of "always" or "never"). Tighten the modality.
- **Fix structural issues first.** `CORE:E:0002` (Instruction File Size Limit) and `CORE:E:0001` (Total Instruction Size Limit) fire deterministically and are easy to satisfy by splitting a too-large root file into per-directory child files. `CORE:S:0012` (Agent Documents Filenames) catches mismatched filenames.
- **Resolve contradictions.** `CORE:C:0026` (Cross Agent Compatibility) and `CORE:C:0046` (Same-Topic Reinforcement and Conflict) tank the score because the agent can't reconcile competing directives. Move shared text to one canonical location.
- **Drop duplication.** `CORE:C:0040` (No Cross-File Duplication) and `CORE:C:0044` (Topic Scatter) flag the same topic appearing in multiple files; consolidate to one source.
- **Add concrete examples.** Rules in the coherence category often check that examples follow general directives — a missing pass / fail pair drops the score even when the directive itself is correct.

## CI gating

By default `ails check` always exits 0. To make CI fail, see [Configuration → Strict mode and minimum score](configuration.md#strict-mode-and-minimum-score) — `--strict` exits non-zero on any finding, and the GitHub Action's `min-score` input adds a post-step gate against the overall score.

## Consistency over time

Score moves should be small commit-to-commit. A sudden drop usually means you removed reinforcement, introduced a contradiction, or pushed a file that exceeds size limits. The CLI tracks score deltas automatically — JSON output (`ails check -f json`) includes `score_delta`, `level_previous`, and `violations_delta` fields when there's a previous run cached, so a CI step can flag the regression without needing to re-run against the previous commit.

## Prevent findings before they happen

`ails check` is the post-hoc loop — file already exists, findings reported. The score is a lagging indicator. The leading indicator is `ails rules`, which gives you the rule set to follow **while** writing, not after. Before authoring a new skill / agent / rule, run:

```bash
ails rules for skill                         # preflight rules for a SKILL.md
ails rules for agent                         # for an agent definition
ails rules for rule -f md                    # markdown output to paste into an authoring prompt
```

See [Rules CLI](rules-cli.md) for full command reference.

---

[← Configuration](configuration.md) · Score Guide · [Rules CLI →](rules-cli.md)
