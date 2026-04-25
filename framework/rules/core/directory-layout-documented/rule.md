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

The main instruction file must include a section documenting the project's directory layout using a heading like "Structure", "Architecture", "Layout", or "Directory" and containing a tree listing or path references. Without a visible directory map, the agent cannot reliably locate or place files.

## Antipatterns

- **Heading without content** like `## Structure` followed by prose that says "see the repo" — the heading matches but the deterministic pattern requires tree characters or path references underneath.
- **Describing layout in prose only** like "Source code lives in the src directory and tests are in tests" — the check requires structural markers (`/`, tree characters) not just prose mentions.
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

Checks for a heading containing "Directory", "Layout", "Structure", or "Tree". Does not verify the section contains an actual directory tree or file listing.
