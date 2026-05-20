---
title: "Reporails CLI Documentation"
description: "AI Instruction Diagnostics for coding agents — index of all CLI docs"
version: "0.5.11"
last_updated: 2026-05-20
---

# Reporails CLI Documentation

AI Instruction Diagnostics for coding agents. Reporails reads your instruction system — root instructions (`CLAUDE.md`, `.github/copilot-instructions.md`, `AGENTS.md`, `.cursorrules`, `GEMINI.md`) plus the rule, skill, sub-agent, and hook files alongside them — and runs 120+ deterministic rules across six rule packs (core + per-agent) to surface the vague directives, contradictions, oversized files, missing reinforcement, and cross-file conflicts that quietly degrade how reliably your agent follows you.

Run it locally with `npx @reporails/cli check` or wire it into CI. Anonymous mode needs no account; signing in raises the rate / payload caps and unlocks the full per-finding fix text. Supports Claude, Codex, Copilot, Cursor, and Gemini.

## Where to start

- **[Getting Started](getting-started.md)** — install, first run, what the output means
- **[Agent Support](agent-support.md)** — which agents are recognized and what's covered
- **[Tiers and Limits](tiers.md)** — anonymous vs signed in, what each mode includes
- **[Configuration](configuration.md)** — disabling rules, project / global config, exclude paths
- **[Score Guide](score-guide.md)** — how the score is built and what it tells you
- **[Rules CLI](rules-cli.md)** — `ails rules list --capability=skill` and friends, preflight rules before authoring
- **[Capability Levels](capability-levels.md)** — the L0–L7 ladder that tells you where your instruction system sits
- **[FAQ](faq.md)** — common questions

## License

[BUSL 1.1](https://github.com/reporails/cli/blob/main/LICENSE) — converts to Apache 2.0 three years after each release.

---

Reporails CLI Documentation · [Getting Started →](getting-started.md)
