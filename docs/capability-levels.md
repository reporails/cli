---
title: "Capability Levels"
description: "The ladder for where AI instructions live and how they act"
version: "0.6.0"
last_updated: 2026-10-04
---

# Capability Levels

`ails check` reports a `Level: L# <Name>` line in the scorecard between `Agent:` and `Scope:`. The level is a read-out, not a gate — every rule fires when its match conditions apply regardless of which level your project is at. Use the level to self-locate; use the symptom table at the bottom to decide when to climb.

## The Ladder

| Level | Name       | What's added                                                    | Channel               |
|-------|------------|-----------------------------------------------------------------|-----------------------|
| L0    | System     | System prompt only                                              | attention             |
| L1    | Primer     | One instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`) | attention             |
| L2    | Composite  | Multiple instruction files in the project; user-level files do not count | attention             |
| L3    | Scoped     | Rule files (`.claude/rules/*.md`, with or without `paths:`) — or, for an agent with no rule-file surface of its own (Codex, Antigravity), a real nested instruction file below the project root | attention             |
| L4    | Delegated  | Skills — procedures invoked on demand                           | attention             |
| L5    | Abstracted | Sub-agents — child contexts called by the parent                | attention (interface) |
| L6    | Governed   | Hooks, deny-permissions                                         | enforcement           |
| L7    | Adaptive   | Self-improving skills written by the agent                      | self-writing          |

The ladder sorts by the channel each rung runs on: soft attention (L0–L5), hard enforcement (L6), self-writing memory (L7). Each rung adds a new diagnostic concern — scope leakage at L3, skill-instruction coherence at L4, governance-instruction alignment at L6, drift detection at L7.

## Channels

- **Attention** — text the model reads and weights against everything else loaded. Fails probabilistically; competes for budget; decays with load. Fixes are content and ordering.
- **Enforcement** — hooks, deny-permissions. Acts outside the model's context. Fails deterministically when configured wrong, never silently. Fixes are scripts, schemas, permission rules. An MCP config is not enforcement: its tool definitions load into the model's context.
- **Self-writing** — agent-authored instructions written between sessions. At read time these land in attention like anything else; at write time the user never saw the prompt that produced them. Fixes are review cadence and explicit auto-memory boundaries.

## Detection

The displayed level is the highest level whose own capability is present. A lower level does not need to be present: skills raise the level to L4 on their own, without rule files.

| Detected                                           | Level            |
|----------------------------------------------------|------------------|
| Auto-memory, learned rules                         | L7  (Adaptive)   |
| Hooks, managed policies (an MCP config on its own does not count) | L6  (Governed)   |
| Sub-agent definitions                              | L5  (Abstracted) |
| Skill definitions                                  | L4  (Delegated)  |
| Rule files (`.claude/rules/`; `paths:` is not required) — or, for Codex / Antigravity, a nested `AGENTS.md` / `GEMINI.md` below the project root | L3  (Scoped)     |
| More than one instruction file in the project (user-level files do not count) | L2  (Composite)  |
| Single main instruction file                       | L1  (Primer)     |
| No instruction files                               | L0  (System)     |

Each level is read on its own, so a project can skip a rung. Observed with `ails check`:

- `CLAUDE.md` plus one skill reads L4 (Delegated), with no rule files.
- `CLAUDE.md` plus hooks in `.claude/settings.json` reads L6 (Governed), with no skills.
- `CLAUDE.md` plus a `.mcp.json` reads L1 (Primer): an MCP config on its own adds no level.
- `CLAUDE.md` plus a `.githooks` folder of plain git hooks reads L1 (Primer): git hooks add no level.
- Claude's auto-memory for the project (kept in your home folder, not in the repository) counts for L7 (Adaptive) when Claude is the agent being checked, so the same project can read L7 on a machine that has it and lower in CI.
- A lone skill with no `CLAUDE.md` reads L4, both with a plain `ails check .` and with `--agent claude`.
- Hooks with no instruction file read L0: `ails check .` prints `No instruction files found.`.

## When to climb

Each rung exists because the rung below it fails in a specific way. The trigger is the failure, not a feature wishlist.

| From | To | Symptom that triggers the climb                                                         |
|------|----|-----------------------------------------------------------------------------------------|
| L0   | L1 | Re-explaining the same project context every session                                    |
| L1   | L2 | One file got long enough that important rules get ignored                               |
| L2   | L3 | Path-irrelevant rules pollute every task — for Claude, Cursor and Copilot that means adding `paths:` scoping to a rule file; for Codex and Antigravity, which have no rule-file surface to scope, it means splitting one `AGENTS.md` into per-directory `AGENTS.md` files |
| L3   | L4 | The same procedure gets described inline across multiple rules                          |
| L4   | L5 | A procedure pollutes the parent's context with reasoning chains the parent doesn't need |
| L5   | L6 | A constraint must hold 100% of the time, not 95%                                        |
| L6   | L7 | You keep correcting the same preference across sessions                                 |

Climbing without a symptom adds structure the model has to navigate without solving a problem you had. Under-climbing is more common: *"agent didn't run tests before pushing"* reads like a prompt-engineering problem but is usually a missing L6 hook; *"agent forgot we use pnpm, not npm"* reads like context drift but is usually a missing L7 memory entry.

---

[← Rules CLI](rules-cli.md) · Capability Levels · [FAQ →](faq.md)
