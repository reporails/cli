---
id: CORE:C:0012
slug: coding-conventions
title: Coding Conventions
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claude-md-guide, claude-md-optimization-study,
  developer-context-cursor-study, dometrain-claude-md-guide, enterprise-claude-usage,
  evaluating-agents-md, fowler-assessing-quality-agents, fowler-context-engineering-agents,
  fowler-pushing-ai-autonomy, microsoft-awesome-copilot-blog, openai-community-agents-md-optimization,
  osmani-ai-coding-workflow, prompthub-cursor-rules-analysis, sewell-agents-md-tips,
  spec-writing-for-agents]
match: {type: main}
---
# Coding Conventions

The instruction file must specify coding conventions — formatting tools, linting rules, and style preferences. Without these, the agent produces code that doesn't match the project's standards.

## Antipatterns

- Describing coding style in prose without a heading containing "Conventions", "Formatting", "Style", or "Lint". The check looks for a matching heading, not convention-related content in other sections.
- Using a heading like "## Rules" or "## Standards" that does not contain any of the matched keywords. Close synonyms do not satisfy the heading check.
- Placing conventions only in a linter config file (`.eslintrc`, `ruff.toml`) without documenting them in the instruction file. The check targets instruction file headings, not config files.

## Pass / Fail

### Pass

~~~~markdown
# MyProject

## Conventions

Use `ruff` for formatting.
Prefer `dataclasses` over plain dicts.
~~~~

### Fail

~~~~markdown
# MyProject

## Architecture

src/ contains domain logic.
tests/ contains pytest suites.
~~~~

## Limitations

Checks for a heading containing "Conventions", "Formatting", "Style", or "Lint". Does not verify the section specifies actionable rules.
