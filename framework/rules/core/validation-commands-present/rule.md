---
id: CORE:C:0008
slug: validation-commands-present
title: Validation Commands Present
category: coherence
type: mechanical
severity: medium
backed_by: [advanced-context-engineering, agent-readmes-empirical-study, awesome-copilot-meta-instructions,
  builder-ai-instruction-best-practices, claude-code-issue-13579, developer-context-cursor-study,
  enterprise-claude-usage, fowler-pushing-ai-autonomy, instruction-limits-principles,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, prompthub-cursor-rules-analysis,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Validation Commands Present

The instruction file must contain a heading matching validation terms (Validation, Verify, QA, Lint, or Check). Documenting validation commands tells the agent which quality gates to run before committing.

## Antipatterns

- Embedding lint commands in a "Commands" section without using a heading that matches validation terms. The check looks for headings containing Validation, Verify, QA, Lint, or Check.
- Using a heading like "## Build" that includes validation steps but does not match the expected terms.
- Listing validation tools in `pyproject.toml` without a corresponding section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## QA

Run `uv run poe qa_fast` for lint + type check.
Run `uv run poe qa` for the full suite.
~~~~

### Fail

~~~~markdown
# Project

## Setup

Install dependencies with `uv sync`.
~~~~

## Limitations

Checks for a heading containing "Validation", "Verify", "QA", "Lint", or "Check". Does not verify the section contains runnable validation commands.
