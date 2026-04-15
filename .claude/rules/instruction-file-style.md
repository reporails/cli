---
description: Instruction file style — actionable content only, no meta-commentary
paths: ["CLAUDE.md", ".claude/rules/**"]
---

# Instruction File Style

Write `CLAUDE.md` and `.claude/rules/*.md` files for AI agent behavior, not user-facing documentation. Every line should be a directive (`Use ruff for formatting`), a constraint (`Do NOT modify .env`), or a concrete reference (`src/reporails_cli/core/pipeline.py`). Actionable content gives the model something to anchor on.

Remove meta-commentary like "this section explains..." or "as mentioned above..." from instruction files. Remove redundant context that restates what the file already says. These patterns waste context tokens without adding coupling.

## Discovery

Applies to files matching `CLAUDE.md` and `.claude/rules/**` via `paths` frontmatter. Loaded automatically by Claude Code from `.claude/rules/`.
