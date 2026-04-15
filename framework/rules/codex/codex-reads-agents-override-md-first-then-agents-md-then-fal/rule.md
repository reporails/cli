---
id: CODEX:S:0001
slug: codex-reads-agents-override-md-first-then-agents-md-then-fal
title: Codex Reads Agents.Override.Md First, Then Agents.Md, Then Fallback 
  Filenames Per Directory Root To Cwd
category: structure
type: deterministic
severity: medium
backed_by:
- codex-agent-loop
- codex-agents-md
- codex-prompting-guide
- codex-skills-guide
- openai-codex-own-agents-md
match: {type: main}
---

# Codex Discovery Chain Documented

Codex discovers instruction files in a specific order: `AGENTS.override.md` first, then `AGENTS.md`, then fallback filenames — walking from the project root to the current working directory. Document this discovery chain so users understand which file takes precedence and where to put overrides.

## Pass / Fail

### Pass

```markdown
# Instructions

Codex reads AGENTS.override.md for local overrides, then falls back to AGENTS.md.
Place machine-specific settings in the override file.
```

### Fail

```markdown
# Instructions

Put your instructions here.
```

## Limitations

Checks for keywords related to the discovery chain (`override`, `fallback`, `precedence`). Does not verify the documented order is technically correct.

