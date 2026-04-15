---
name: add-changelog-entry
description: Add a changelog entry to UNRELEASED.md
---

# /add-changelog-entry

Add a changelog entry to `UNRELEASED.md` based on recent changes.

## Process

1. Run `git diff` or check recent file modifications to determine what changed
2. Determine the **area** from the file path:
   - `src/reporails_cli/interfaces/cli/` → `[CLI]`
   - `src/reporails_cli/core/` → `[CORE]`
   - `src/reporails_cli/bundled/` → `[BUNDLED]`
   - `src/reporails_cli/formatters/` → `[FORMATTERS]`
   - `README.md`, `docs/` → `[DOCS]`
   - `CLAUDE.md`, `.ails/backbone.yml`, `.claude/` → `[META]`
3. Determine the **category**: Added (new files/content), Changed (modified existing), Deprecated, Removed, Fixed (bug fixes), Security
4. Write a concise description (3-7 words)
5. Append to `UNRELEASED.md` under the correct `### [Category]` section — create the section if it doesn't exist

## Format

```markdown
### [Category]
- [Area]: Description
```

Append directly without asking for confirmation.
