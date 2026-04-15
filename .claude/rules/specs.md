---
description: Spec file accuracy — specs must match implementation
paths: ["docs/specs/**"]
---

# Specification Files

Update `docs/specs/*.md` when changing behavior in `src/reporails_cli/core/`. Function signatures, return types, and interfaces in specs must match what `checks.py`, `rule_runner.py`, and `content_checker.py` actually implement.

Remove features from `docs/specs/` when removing them from `src/`. Add features to specs when adding them to code. Specs document what exists in the current codebase — not aspirational features or planned work.

## Discovery

Applies to files matching `docs/specs/**` via `paths` frontmatter. Loaded automatically by Claude Code from `.claude/rules/`.
