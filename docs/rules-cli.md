---
title: "Rules CLI"
description: "Browse the framework rule registry and assemble preflight rule sets for authoring"
version: "0.5.11"
last_updated: 2026-06-17
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

Every rule in the registry, filterable. Filters compose.

```bash
ails rules list                              # all rules across all agents
ails rules list --capability=skill           # rules whose match.type includes skill
ails rules list --capability=skill --capability=agent  # multiple capabilities (repeatable)
ails rules list --agent=claude               # CORE + CLAUDE rules only
ails rules list --severity=high              # critical + high severity rules
ails rules list --format=json                # structured output for tooling
```

`--severity` accepts `critical`, `high`, `medium`, `low` — interpreted as **at or above** (so `--severity=high` returns `critical` + `high`).

Workflow-ordered preflight: pass `--capability` and use `--format=md` to pipe rules straight into an authoring agent's prompt. The output groups by category in writing order:

1. **structure** — get the shape right first (frontmatter, file location, links resolve)
2. **direction** — directive instructions are clear, no ambiguity
3. **coherence** — content consistent, no contradictions
4. **efficiency** — keep within context budget
5. **maintenance** — keep fresh, no stale refs
6. **governance** — policy alignment

Within each category, rules are sorted by severity (critical → high → medium → low). The operator (or agent) reads top-down and addresses concerns in the right order.

### `ails rules agents`

Enumerate known agents (`claude`, `codex`, `copilot`, `cursor`, `gemini`, ...).

```bash
ails rules agents
ails rules agents -f json
```

### `ails rules capabilities`

Enumerate the capability vocabulary an agent declares (`skills`, `agents`, `main`, `hooks`, ...). Detects current project's agent by default; override with `--agent`.

```bash
ails rules capabilities                      # auto-detect agent from cwd
ails rules capabilities --agent=claude       # explicit
ails rules capabilities --agent=claude -f json
```

For each capability the text output shows the resolved path glob it scans and the number of matching targets in the current project, so you can see at a glance what `ails check <capability>` would actually pick up:

```
Capabilities for claude (5):
  skills  .claude/skills/**/SKILL.md  10 found
  agents  .claude/agents/**/*.md      3 found
  ...
```

The JSON form keeps the flat `capabilities` name list and adds a `resolution` array alongside it — one entry per capability with `name`, `resolves_to` (the path glob), and `found` (the count of matching targets):

```json
{
  "agent": "claude",
  "capabilities": ["agents", "main", "rules", "skills"],
  "resolution": [
    { "name": "skills", "resolves_to": ".claude/skills/**/SKILL.md", "found": 10 }
  ]
}
```

### `ails explain <id-or-slug>`

Single-rule detail: title, category, severity, type, body, and pass/fail examples. Accepts a rule ID or a slug (run `ails --install-completion` once for tab completion).

```bash
ails explain CORE:S:0024                     # by ID
ails explain section-headers-present         # by slug
```

## Output formats

### Text (`-f text`, default)

Compact terminal output. Rule IDs, severity, titles only. Useful for quick scans.

### Markdown (`-f md`)

Rich output suitable for piping into an agent's context. Default behavior includes Pass / Fail example blocks pulled from each rule's `rule.md` body. `--no-examples` strips them for a shorter context payload.

```bash
ails rules list --capability=skill --agent=claude -f md > skill-preflight.md
# Paste skill-preflight.md into your authoring agent's prompt before writing.
```

### JSON (`-f json`)

Stable structured payload for tooling. Top-level keys: `capability`, `capabilities`, `agent`, `agents_loaded`, `count`, `checks`. Each entry in `checks` has `id`, `title`, `slug`, `category`, `severity`, `type`, and `match`. For rule bodies and Pass / Fail examples, use the markdown format (`-f md`) or the text view `ails explain <id>`.

## Integration patterns

### Pipe into an authoring agent

```bash
ails rules list --capability=skill --agent=claude -f md | claude code "Write a skill called 'analyze-test-coverage' following these rules"
```

The agent receives the rule set as context before writing. Output should pass `ails check skills:analyze-test-coverage` on the first run.

### Custom Claude Code agent

Add a slash command that wraps `ails rules`:

```markdown
---
description: Fetch reporails rules for authoring a {{capability}}
---

Run `ails rules list --capability={{capability}} -f md` and follow the rules when writing the requested file.
```

### CI gate

```yaml
# Before opening a PR that adds a new skill, run preflight:
- run: ails rules list --capability=skill -f md > preflight.md
- run: # ... your authoring step
- run: ails check skills:<new-skill-name> --strict
```

## Related

- [Score Guide](score-guide.md) — how findings compose into a score
- [Capability Levels](capability-levels.md) — read-out of project architectural maturity
- [Configuration](configuration.md) — `.ails/config.yml` options

---

[← Score Guide](score-guide.md) · Rules CLI · [Capability Levels →](capability-levels.md)
