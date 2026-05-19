---
title: "Rules CLI"
description: "Browse the framework rule registry and assemble preflight rule sets for authoring"
version: "0.5.11"
last_updated: 2026-05-19
---

# Rules CLI

`ails rules` exposes the framework rule set as a queryable registry. Use it to fetch the rules that apply **before** writing a skill, agent, rule, or instruction file — write compliant content from the start instead of patching lint findings after.

## Why preflight

`ails check` runs after a file is on disk and reports what's wrong. `ails rules` runs before and tells you what to do. The shift:

| Old loop | New loop |
|---|---|
| Write → lint → patch findings → re-lint | Preflight → write compliant → lint passes |

For an AI coding agent about to author a SKILL.md, the preflight output becomes context that shapes the draft. Catastrophe patterns (8 rule violations on a fresh skill) drop sharply when the agent reads the constraints first.

## Commands

### `ails rules list`

Every rule in the registry, filterable.

```bash
ails rules list                              # all rules across all agents
ails rules list --capability=skill           # rules whose match.type includes skill
ails rules list --agent=claude               # CORE + CLAUDE rules only
ails rules list --severity=high              # critical + high severity rules
ails rules list --format=json                # structured output for tooling
```

Filters compose. `--severity` accepts `critical`, `high`, `medium`, `low` — the value is interpreted as **at or above** (so `--severity=high` returns `critical` + `high`).

### `ails rules for <capability>`

Workflow-ordered preflight: the rules applicable when authoring a file of the given capability, sorted in writing order.

```bash
ails rules for skill                         # rules to follow when writing a SKILL.md
ails rules for agent                         # rules for agent definitions
ails rules for rule                          # rules for .claude/rules/*.md files
ails rules for main                          # rules for CLAUDE.md / AGENTS.md
```

Output is grouped by category in the order that matches the authoring workflow:

1. **structure** — get the shape right first (frontmatter, file location, links resolve)
2. **direction** — directive instructions are clear, no ambiguity
3. **coherence** — content consistent, no contradictions
4. **efficiency** — keep within context budget
5. **maintenance** — keep fresh, no stale refs
6. **governance** — policy alignment

Within each category, rules are sorted by severity (critical → high → medium → low). This means the operator (or agent) reads top-down and addresses concerns in the right order.

### `ails rules explain <id>`

Single-rule detail: title, category, severity, type, body, and pass/fail examples from the rule's documentation.

```bash
ails rules explain CORE:S:0024               # text — for terminal browsing
ails rules explain CORE:S:0024 -f md         # markdown — for piping into agent context
ails rules explain CORE:S:0024 -f json       # structured
```

## Output formats

### Text (`-f text`, default)

Compact terminal output. Rule IDs, severity, titles only. Useful for quick scans.

### Markdown (`-f md`)

Rich output suitable for piping into an agent's context. Default behavior includes Pass / Fail example blocks pulled from each rule's `rule.md` body. `--no-examples` strips them for a shorter context payload.

```bash
ails rules for skill --agent=claude -f md > skill-preflight.md
# Paste skill-preflight.md into your authoring agent's prompt before writing.
```

### JSON (`-f json`)

Stable structured payload for tooling. Top-level keys: `capability`, `agent`, `agents_loaded`, `count`, `rules`. Each rule entry has `id`, `title`, `slug`, `category`, `severity`, `type`, and `match`. `explain` additionally returns `body` and `examples: {pass, fail}`.

## Integration patterns

### Pipe into an authoring agent

```bash
ails rules for skill --agent=claude -f md | claude code "Write a skill called 'analyze-test-coverage' following these rules"
```

The agent receives the rule set as context before writing. Output should pass `ails check skill analyze-test-coverage` on the first run.

### Custom Claude Code agent

Add a slash command that wraps `ails rules`:

```markdown
---
description: Fetch reporails rules for authoring a {{capability}}
---

Run `ails rules for {{capability}} -f md` and follow the rules when writing the requested file.
```

### CI gate

```yaml
# Before opening a PR that adds a new skill, run preflight:
- run: ails rules for skill -f md > preflight.md
- run: # ... your authoring step
- run: ails check skill <new-skill-name> --strict
```

## Related

- [Score Guide](score-guide.md) — how findings compose into a score
- [Capability Levels](capability-levels.md) — read-out of project architectural maturity
- [Configuration](configuration.md) — `.ails/config.yml` options

---

[← Score Guide](score-guide.md) · Rules CLI · [Capability Levels →](capability-levels.md)
