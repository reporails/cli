---
id: CODEX:S:0001
slug: override-read-order
title: "Override Read Order"
category: structure
type: deterministic
severity: medium
backed_by: []
match: {type: main}
source: https://developers.openai.com/codex/guides/agents-md
---

# Codex Discovery Chain Documented

Codex discovers instruction files in a specific order: `AGENTS.override.md` first, then `AGENTS.md`, then fallback filenames — walking from the project root to the current working directory. Document this discovery chain so users understand which file takes precedence and where to put overrides.

## Antipatterns

- **Undocumented override file.** Creating `AGENTS.override.md` for local settings without mentioning it in the main `AGENTS.md`. Collaborators don't know it exists or how it interacts with the base file.
- **Wrong precedence assumption.** Assuming `AGENTS.md` overrides `AGENTS.override.md` (the opposite is true). Users put critical config in the wrong file and it gets silently overridden.
- **Single-file instructions.** Putting everything in one `AGENTS.md` without documenting that Codex supports the override chain. Users who need machine-specific settings modify the committed file instead of using the override.

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

