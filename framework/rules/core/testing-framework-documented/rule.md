---
id: CORE:C:0005
slug: testing-framework-documented
title: Testing Framework Documented
category: coherence
type: mechanical
severity: medium
backed_by: [advanced-context-engineering, agent-readmes-empirical-study, agentic-coding-adoption-github,
  agents-md-impact-efficiency, awesome-copilot-meta-instructions, claude-md-optimization-study,
  developer-context-cursor-study, openai-community-agents-md-optimization, osmani-ai-coding-workflow,
  prompthub-cursor-rules-analysis, spec-writing-for-agents]
match: {type: main}
---
# Testing Framework Documented

The instruction file must contain a heading matching testing terms (Testing, Tests, or Test). Documenting the testing framework tells the agent which tool to use, where tests live, and how to run them.

## Antipatterns

- Embedding test commands inline without a heading. Writing `uv run pytest` in a "Commands" section does not satisfy the check -- there must be a heading containing "Testing", "Tests", or "Test".
- Using a heading like "## Quality" or "## Validation" that covers testing but does not match the expected terms.
- Relying on the test runner's own documentation instead of including a testing section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Testing

Run `uv run pytest tests/ -v` for the full suite.
Test files use `test_` prefix with `pytest` fixtures.
~~~~

### Fail

~~~~markdown
# Project

## Commands

Run the linter and quality checks.
Make sure everything passes before committing.
~~~~

## Limitations

Checks for a heading containing "Testing", "Tests", or "Test". Does not verify the section describes how to run tests or which framework is used.
