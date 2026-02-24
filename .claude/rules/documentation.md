---
paths: ["docs/*.md", "README.md"]
---

# User-Facing Documentation

These files are read by people, not coding agents.

- These files are for user-facing documentation, not AI agent instructions
- Commands must be copy-pasteable and working (`ails check .`, not `reporails check .`)
- Examples must reflect actual CLI behavior
- Only document features that exist; remove references to unimplemented features
- Keep installation/usage sections current with pyproject.toml
- Use consistent terminology: "rules" not "checks" in user-facing text
- When fixing errors, make targeted edits — don't rewrite sections and lose valid content
