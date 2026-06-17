---
title: "Score Guide"
description: "How the score is built and what it tells you"
version: "0.5.11"
last_updated: 2026-06-17
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

The score is a single verdict on how well-formed your instructions are — not a tally of findings (those are a separate worklist beneath it). It reflects:

1. **How clearly your instructions are written** — specific, well-formatted directives that don't contradict each other score higher than vague, buried, or conflicting ones.
2. **Delivery** — whether your instructions actually reach the agent intact. Missing required structure, or content pushed past an agent's hard instruction-size limit (where the overflow is silently dropped before the agent ever sees it), pulls the score down.
3. **Per-surface health** — each instruction surface (Main / Rules / Skills / Agents / Memory) contributes its own score to the overall picture.

Files with no scorable instruction content — a non-instruction surface a coding agent still reads (like a `.cursorignore` path list) or an empty instruction file — show as `not scored` and don't count toward any surface or the overall number.

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

In supporting terminals the rule IDs in the text output are clickable links to their docs page.

Anonymous runs show summary findings and cross-file conflict counts — enough to see whether your instructions are working. Sign in with `ails auth login` to unlock full per-finding fix text and the exact location of each cross-file conflict. See [Tiers and Limits](tiers.md) for the side-by-side breakdown of what each mode includes.

## How findings are triaged by leverage

The score is the analysis service's single quality verdict; the `Findings` line beneath it is a separate worklist. To help you spend effort where it counts, findings are sorted by **leverage** — how much fixing one is likely to move the score — into three tiers:

- **gate-mover** — fixing it is likely to move the score the most. These are the entries to clear first.
- **conditional** — worth fixing, but the score impact depends on the rest of the file.
- **cosmetic** — stylistic or local; clearing it rarely moves the number.

Low-leverage findings don't clutter the default view: they collapse into a single `+N lower-priority (won't move your score yet)` line. Run `ails check -v` to expand them. Each shown finding may also carry an indented `→` action line — the concrete next step the rule recommends.

Leverage is computed **per file**, so the same rule can rank differently in different files — a finding that's a gate-mover in a weak file may be cosmetic in a strong one. The leverage triage is a worklist aid, not a re-weighting of the score: the score is a single quality verdict, not a severity-weighted tally of findings.

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

Score moves should be small commit-to-commit. A sudden drop usually means you removed reinforcement, introduced a contradiction, or pushed a file that exceeds size limits. To track score over time in CI, record the score from each run (the GitHub Action exposes a `score` output) and compare across commits.

## Prevent findings before they happen

`ails check` is the post-hoc loop — file already exists, findings reported. The score is a lagging indicator. The leading indicator is `ails rules`, which gives you the rule set to follow **while** writing, not after. Before authoring a new skill / agent / rule, run:

```bash
ails rules list --capability=skill                  # preflight rules for a SKILL.md
ails rules list --capability=agent                  # for an agent definition
ails rules list --capability=rule -f md             # markdown output to paste into an authoring prompt
```

See [Rules CLI](rules-cli.md) for full command reference.

---

[← Configuration](configuration.md) · Score Guide · [Rules CLI →](rules-cli.md)
