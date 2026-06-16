---
id: CORE:E:0001
slug: total-instruction-size-limit
title: Total Instruction Size Limit
category: efficiency
type: mechanical
severity: medium
backed_by: [advanced-context-engineering, agents-md-impact-efficiency, developer-context-cursor-study,
  fowler-context-engineering-agents, lost-in-the-middle-long-contexts, osmani-ai-coding-workflow,
  spec-writing-for-agents]
match: {format: freeform}
fix: |
  Trim the always-loaded surface. Keep eager files — the main instruction
  file, its imports, and the memory index — lean, targeting the whole
  one-round footprint under 100 KB. Move depth into skills, on-demand rules,
  or linked topic files; those load only when needed and are not counted.
---

# Total Instruction Size Limit

The always-injected ("one round") instruction footprint should stay under 100 KB (102,400 bytes). This counts what the agent loads every turn: eager instruction files (the main file + its imports + the memory index) in full, and progressive-disclosure surfaces (skills, subagents) by their name + description metadata only. On-demand rules, recalled memory entries, and skill / agent bodies load only when needed and are not counted. A bloated always-on footprint wastes context budget every turn and dilutes every instruction it carries.

This is an advisory ceiling. Agents that enforce a hard, lower cap with silent truncation — such as Codex's 32 KiB `AGENTS.md` limit — have their own stricter rule that supersedes this one.

## Antipatterns

- Putting extensive documentation and examples in the eager instruction file instead of a skill or on-demand rule that loads only when relevant.
- Duplicating instructions across eager files. Each copy adds to the every-turn footprint without adding value.
- Embedding large code blocks or data tables in the main instruction file. Reference external files instead.
- Not monitoring the eager footprint as the project grows — individual files may be small, but the always-on aggregate can creep up.

## Pass / Fail

### Pass

~~~~markdown
Eager footprint of ~38 KB:
  CLAUDE.md (15 KB) + MEMORY.md index (5 KB) + 30 skills (~0.6 KB metadata each)
Total one-round footprint: ~38 KB -- well under 100 KB.
(Skill bodies and on-demand rules are not counted -- they load only when used.)
~~~~

### Fail

~~~~markdown
Eager footprint of ~120 KB:
  CLAUDE.md (90 KB) + 12 @-imported topic files (~2.5 KB each)
Total one-round footprint: ~120 KB -- exceeds 100 KB every turn.
~~~~

## Limitations

Counts the always-injected footprint, not every file on disk: eager files in full, skills / subagents by metadata only, on-demand and recalled surfaces excluded. Advisory — it does not break down which eager files over-contribute. Agents with a hard, enforced cap have a dedicated superseding rule.
