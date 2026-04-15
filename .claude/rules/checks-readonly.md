---
description: Bundled config protection — never modify without explicit instruction
paths: ["src/reporails_cli/bundled/**"]
---

# Bundled Config Files

Leave `src/reporails_cli/bundled/capability-patterns.yml` unchanged unless the user explicitly asks for a modification. This file contains regex patterns for agent capability detection — it is CLI-owned orchestration logic, not a framework rule file under `framework/rules/`.

## Discovery

Applies to files matching `src/reporails_cli/bundled/**` via `paths` frontmatter. Loaded automatically by Claude Code from `.claude/rules/`.
