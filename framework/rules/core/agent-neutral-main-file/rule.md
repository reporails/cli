---
id: CORE:C:0032
slug: agent-neutral-main-file
title: "Agent Neutral Main File"
category: coherence
type: deterministic
severity: high
backed_by: []
match: {format: freeform}
---

# Agent Neutral Main File

The main instruction file must not contain agent-specific directives. Agent-specific syntax belongs in dedicated agent files, not the shared root.

## Antipatterns

- Writing "Claude Code requires this format" in the main instruction file. The check detects agent names followed by directive words like "specific", "only", or "require".
- Adding "Copilot only supports single-file mode" to the shared root. Even factual statements trigger the check when they combine an agent name with a directive keyword.
- Using "Cursor-specific extensions" as a heading in the main file. Agent-specific content belongs in a dedicated agent file, not the shared root.

## Pass / Fail

### Pass

~~~~markdown
# Project Instructions

Use `ruff` for formatting.
Run `uv run pytest` before committing.
Keep modules under 500 lines.
~~~~

### Fail

~~~~markdown
# Project Instructions

Claude Code specific: always use the Read tool first.
Copilot only supports inline completions here.
~~~~

## Limitations

Detects agent-specific directives that name particular tools (Claude Code, Copilot, Cursor). Does not evaluate whether the content is functionally agent-neutral.
