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

## Constraints

- One concern per file (e.g., access control separate from styling)
- Keep under 500 lines — everything consumes tokens
- Use descriptive filenames (`api-validation.md` not `rules1.md`)
- Add `paths` frontmatter to scope rules to relevant files; omit for global rules
