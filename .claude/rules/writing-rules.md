---
paths: [".claude/rules/**"]
---

# Writing Rule Files

Rule files in `.claude/rules/` are loaded into Claude's context.

## Format

```markdown
---
paths: ["src/**/*.py"]  # Optional: scope to specific files
---

# Rule Title

- Actionable instruction
- Another instruction
```

## Guidelines

- One concern per file (security separate from styling)
- Keep under 500 lines - everything consumes tokens
- Use descriptive filenames (`api-validation.md` not `rules1.md`)
- Add `paths` frontmatter to reduce noise when not relevant
- No paths = loads globally for all files
- Content MUST be actionable, not explanatory
