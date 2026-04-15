---
description: User-facing documentation — copy-pasteable commands, no aspirational content
paths: ["docs/*.md", "README.md"]
---

# User-Facing Documentation

Write `docs/*.md` and `README.md` for people, not coding agents. Commands must be copy-pasteable and working — use `ails check .` not `reporails check .`. Examples must reflect actual CLI behavior from `uv run ails --help`.

- Keep installation and usage sections current with `pyproject.toml` version and dependencies
- Use "rules" not "checks" in user-facing text — consistent with CLI output from `uv run ails check`
- Only document features that exist in `src/reporails_cli/`. Remove references to unimplemented features.
- When fixing errors, make targeted edits — rewriting entire sections risks losing valid content

## Discovery

Applies to files matching `docs/*.md` and `README.md` via `paths` frontmatter. Loaded automatically by Claude Code from `.claude/rules/`.
