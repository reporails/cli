---
id: CORE:E:0002
slug: instruction-file-size-limit
title: Instruction File Size Limit
category: efficiency
type: mechanical
severity: high
backed_by: [advanced-context-engineering, agent-readmes-empirical-study, builder-ai-instruction-best-practices,
  claude-md-guide, claudemd-best-practices-mermaid-for-workflows, developer-context-cursor-study,
  dometrain-claude-md-guide, enterprise-claude-usage, evaluating-agents-md, fowler-context-engineering-agents,
  fowler-pushing-ai-autonomy, instruction-limits-principles, lost-in-the-middle-long-contexts,
  monorepo-claude-md-organization, openai-community-agents-md-optimization, rules-directory-mechanics,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {format: freeform}
---

# Instruction File Size Limit

Individual instruction files must stay within size limits. Oversized files exceed context windows and degrade agent performance. The check enforces a maximum of 300 lines per file.

## Antipatterns

- **Monolithic instruction file**: Putting all project instructions in a single `CLAUDE.md` that grows past 300 lines. Split into `.claude/rules/*.md` files by topic instead.
- **Embedded large examples**: Including full code samples or log output inline that push the file past the line limit. Reference external files or keep examples to 3-5 lines.
- **Duplicated instructions across sections**: Restating the same instruction in multiple sections inflates the file without adding information. State each instruction once.

## Pass / Fail

### Pass

~~~~markdown
# Project (48 lines)
## Commands
## Conventions
## Boundaries
~~~~

### Fail

~~~~markdown
# Project (350 lines)
## Commands (50 lines)
## Conventions (120 lines)
## Full API Reference (180 lines)
~~~~

## Limitations

Counts raw lines (max 300) regardless of line length or content density. A file with 300 single-word lines and one with 300 dense paragraphs are treated equally.
