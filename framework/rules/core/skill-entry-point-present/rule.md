---
id: CORE:S:0015
slug: skill-entry-point-present
title: Skill Entry Point Present
category: structure
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents]
match: {type: skill}
fix: |
  Add a `SKILL.md` file at the skill directory's root with YAML
  frontmatter (`name:`, `description:`) and a body describing what the
  skill does. The skill loader discovers skills via this entry-point
  filename; directories without `SKILL.md` are invisible.
---
# Skill Entry Point Present

Every directory under a skills root (e.g. `.claude/skills/<name>/`) must contain a `SKILL.md` file. `SKILL.md` is the entry point the agent's skill loader uses to discover and invoke a skill — a skill directory without it is invisible to the agent.

Skills-root directories are found by locating existing `SKILL.md` files, then each immediate subdirectory of a skills root is checked for its own `SKILL.md`.

## Antipatterns

- Creating a skill directory with workflow or asset files but no `SKILL.md` at its root. Without the entry point, the loader never sees the skill.
- Naming the entry point `README.md`, `index.md`, or `skill.md` (lowercase) instead of `SKILL.md`. The loader matches the exact filename `SKILL.md`.
- Leaving a stray, non-skill directory directly under a skills root. Everything immediately under `skills/` is treated as a skill and is expected to carry a `SKILL.md`.

## Pass / Fail

### Pass

~~~~text
.claude/skills/
  commit/
    SKILL.md
  review/
    SKILL.md
~~~~

### Fail

~~~~text
.claude/skills/
  commit/
    SKILL.md
  review/
    notes.md        # no SKILL.md — skill is undiscoverable
~~~~

## Limitations

Checks immediate subdirectories of each skills root for a `SKILL.md` file. Skills roots are located by globbing for existing `SKILL.md` files, so a skills root where *every* subdirectory lacks `SKILL.md` (no discoverable entry point anywhere) is not detected. Aggregates across the whole skills tree, so it runs on whole-project scans only and is skipped under targeted scope.
