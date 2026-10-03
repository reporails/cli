---
id: CORE:C:0035
slug: directory-layout-documented
title: Directory Layout Documented
category: coherence
type: deterministic
severity: high
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claude-md-optimization-study, claudemd-best-practices-backbone-yml-pattern,
  developer-context-cursor-study, dometrain-claude-md-guide, evaluating-agents-md,
  fowler-pushing-ai-autonomy, instruction-limits-principles, sewell-agents-md-tips,
  spec-writing-for-agents]
match: {type: main}
---

# Directory Layout Documented

The main instruction file must document the project's directory layout. This is satisfied by either a heading such as "Structure", "Architecture", "Layout", or "Directory", or a visible tree listing / path references (`src/`, `tests/`, tree-drawing characters). Without a visible directory map, the agent cannot reliably locate or place files.

## Antipatterns

- **Describing layout in prose only** like "Source code lives in the src directory and tests are in tests" — the check needs a recognized heading or a structural marker (a path with `/`, tree-drawing characters), not just prose mentions.
- **No layout section or tree anywhere** — a main file with neither a Structure/Architecture/Layout/Directory heading nor any tree/path listing.
- **Layout in a separate file** with no reference in the main file — the check targets `type: main`, so the layout must appear in `CLAUDE.md` or equivalent.

## Pass / Fail

### Pass

~~~~markdown
## Structure
```
src/
├── core/
├── interfaces/
└── formatters/
tests/
```
~~~~

### Fail

~~~~markdown
The project has source code and tests organized in directories.
See the repository for the full structure.
~~~~

## Limitations

Satisfied by any of: a heading matching Structure, Architecture, Layout, or Directory; tree-drawing characters; or a `src/` or `tests/` path reference. A single such marker passes — the check does not verify that a matching heading is actually followed by a real directory tree, nor that a tree lists every top-level directory.
