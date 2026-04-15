---
description: Rule file authoring — format, scope, and constraints for .claude/rules/
paths: [".claude/rules/**"]
---

# Writing Rule Files

Rule files in `.claude/rules/` are loaded into Claude's context at session start.

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

- Keep each `.claude/rules/*.md` file focused on one concern — access control separate from styling, testing separate from documentation
- Keep files under 500 lines — every line consumes context tokens
- Use descriptive filenames like `api-validation.md` not `rules1.md`
- Add `paths` or `globs` frontmatter to scope rules to relevant files under `src/`, `tests/`, or `docs/`. Omit for global rules.

## Discovery

Applies to files matching `.claude/rules/**` via `paths` frontmatter. Loaded automatically by Claude Code from `.claude/rules/`.
