---
title: "Capability Levels"
description: "The ladder for where AI instructions live and how they act"
version: "0.5.11"
last_updated: 2026-06-06
---

# Capability Levels

`ails check` reports a `Level: L# <Name>` line in the scorecard between `Agent:` and `Scope:`. The level is a read-out, not a gate — every rule fires when its match conditions apply regardless of which level your project is at. Use the level to self-locate; use the symptom table at the bottom to decide when to climb.

## The Ladder

| Level | Name       | What's added                                                    | Channel               |
|-------|------------|-----------------------------------------------------------------|-----------------------|
| L0    | System     | System prompt only                                              | attention             |
| L1    | Primer     | One instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`) | attention             |
| L2    | Composite  | Multiple files — user defaults, project overrides               | attention             |
| L3    | Scoped     | Path-scoped rules (`.claude/rules/*.md`)                        | attention             |
| L4    | Delegated  | Skills — procedures invoked on demand                           | attention             |
| L5    | Abstracted | Sub-agents — child contexts called by the parent                | attention (interface) |
| L6    | Governed   | Hooks, MCP gates, deny-permissions                              | enforcement           |
| L7    | Adaptive   | Self-improving skills written by the agent                      | self-writing          |

The ladder sorts by the channel each rung runs on: soft attention (L0–L5), hard enforcement (L6), self-writing memory (L7). Each rung adds a new diagnostic concern — scope leakage at L3, skill-instruction coherence at L4, governance-instruction alignment at L6, drift detection at L7.

## Channels

- **Attention** — text the model reads and weights against everything else loaded. Fails probabilistically; competes for budget; decays with load. Fixes are content and ordering.
- **Enforcement** — hooks, MCP gates, deny-permissions. Acts outside the model's context. Fails deterministically when configured wrong, never silently. Fixes are scripts, schemas, permission rules.
- **Self-writing** — agent-authored instructions written between sessions. At read time these land in attention like anything else; at write time the user never saw the prompt that produced them. Fixes are review cadence and explicit auto-memory boundaries.

## Detection

The displayed level is the highest architectural capability present, cumulative — every level below must also pass.

| Detected                                           | Level            |
|----------------------------------------------------|------------------|
| Auto-memory, learned rules                         | L7  (Adaptive)   |
| Hooks, MCP servers, managed policies               | L6  (Governed)   |
| Sub-agent definitions                              | L5  (Abstracted) |
| Skill definitions                                  | L4  (Delegated)  |
| Path-scoped rules (`.claude/rules/` with `paths:`) | L3  (Scoped)     |
| Multiple main files, user defaults, overwrites     | L2  (Composite)  |
| Single main instruction file                       | L1  (Primer)     |
| No instruction files                               | L0  (System)     |

A project with skills but no path-scoped rules still displays L4 — the gate engine walks L1 → L2 → ... → L7 cumulatively. Hub-only repos that ship hooks but no instructions sit at L0 with an enforcement layer; the level reads the soft channel.

## When to climb

Each rung exists because the rung below it fails in a specific way. The trigger is the failure, not a feature wishlist.

| From | To | Symptom that triggers the climb                                                         |
|------|----|-----------------------------------------------------------------------------------------|
| L0   | L1 | Re-explaining the same project context every session                                    |
| L1   | L2 | One file got long enough that important rules get ignored                               |
| L2   | L3 | Path-irrelevant rules pollute every task                                                |
| L3   | L4 | The same procedure gets described inline across multiple rules                          |
| L4   | L5 | A procedure pollutes the parent's context with reasoning chains the parent doesn't need |
| L5   | L6 | A constraint must hold 100% of the time, not 95%                                        |
| L6   | L7 | You keep correcting the same preference across sessions                                 |

Climbing without a symptom adds structure the model has to navigate without solving a problem you had. Under-climbing is more common: *"agent didn't run tests before pushing"* reads like a prompt-engineering problem but is usually a missing L6 hook; *"agent forgot we use pnpm, not npm"* reads like context drift but is usually a missing L7 memory entry.

---

[← Rules CLI](rules-cli.md) · Capability Levels · [FAQ →](faq.md)
