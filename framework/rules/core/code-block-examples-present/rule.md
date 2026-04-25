---
id: CORE:C:0016
slug: code-block-examples-present
title: Code Block Examples Present
category: coherence
type: mechanical
severity: medium
backed_by: [agent-readmes-empirical-study, awesome-copilot-meta-instructions, builder-ai-instruction-best-practices,
  claudemd-best-practices-mermaid-for-workflows, developer-context-cursor-study, dometrain-claude-md-guide,
  flowbench-workflow-format-benchmark, fowler-pushing-ai-autonomy, openai-community-agents-md-optimization,
  osmani-ai-coding-workflow, sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Code Block Examples Present

The instruction file must contain fenced code blocks with concrete examples. Code blocks are the clearest way to show the agent exact syntax and patterns.

## Antipatterns

- Writing commands in inline code (`` `npm test` ``) without any fenced code block. The check looks for fenced code blocks (triple backtick blocks), not inline code spans.
- Providing examples only as prose descriptions ("run the test suite, then check coverage"). Without a fenced code block, the agent has no copy-pasteable syntax to follow.
- Including a single empty code block as a placeholder. The check verifies code blocks exist but a trivially empty block provides no value.

## Pass / Fail

### Pass

~~~~markdown
# MyProject

## Commands

```bash
uv run pytest tests/ -v
uv run ruff check src/
```
~~~~

### Fail

~~~~markdown
# MyProject

## Commands

Run `pytest` for tests and `ruff` for linting.
Use the standard test runner.
~~~~

## Limitations

Checks for the presence of code blocks. Does not evaluate whether the code examples are correct or complete.
