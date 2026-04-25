---
id: CORE:S:0010
slug: modular-file-organization
title: Modular File Organization
category: structure
type: mechanical
severity: high
backed_by: [agents-md-impact-efficiency, builder-ai-instruction-best-practices, claude-md-guide,
  claudemd-best-practices-mermaid-for-workflows, fowler-context-engineering-agents,
  instruction-limits-principles, rules-directory-mechanics, spec-writing-for-agents]
match: {format: freeform}
---

# Modular File Organization

A project must contain at least 2 instruction files. Splitting instructions across multiple files keeps each file focused and prevents a single monolithic document from growing unwieldy.

## Antipatterns

- Putting all instructions in a single `CLAUDE.md` with no scoped rule files -- the check requires a minimum of 2 instruction files in the project.
- Creating a second file that is empty or contains only a title -- the file count check counts files that exist, but the content may fail other rules.
- Placing all scoped rules in subdirectories but having no root instruction file -- the file_exists gate checks that the expected root file is present before counting.

## Pass / Fail

### Pass

~~~~markdown
CLAUDE.md              (main instruction file)
.claude/rules/testing.md   (scoped rule)
.claude/rules/style.md     (scoped rule)
~~~~

### Fail

~~~~markdown
CLAUDE.md              (single file, no other instruction files)
~~~~

## Limitations

Counts instruction files and enforces a minimum of 2. Does not evaluate whether the files are meaningfully different — two duplicate files would pass.
