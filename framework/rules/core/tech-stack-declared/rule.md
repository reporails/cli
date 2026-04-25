---
id: CORE:C:0034
slug: tech-stack-declared
title: Tech Stack Declared
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claude-md-optimization-study, developer-context-cursor-study,
  dometrain-claude-md-guide, fowler-context-engineering-agents, fowler-pushing-ai-autonomy,
  instruction-limits-principles, microsoft-awesome-copilot-blog, openai-community-agents-md-optimization,
  osmani-ai-coding-workflow, prompthub-cursor-rules-analysis, sewell-agents-md-tips,
  spec-writing-for-agents]
match: {type: main}
---
# Tech Stack Declared

The root instruction file must contain a heading matching technology terms (Stack, Tech, Language, Runtime, or Framework). Declaring the tech stack prevents the agent from guessing or suggesting incompatible technologies.

## Antipatterns

- Mentioning technologies only in prose without a dedicated heading. The check requires a heading containing one of the matching terms, not inline references.
- Using a heading like "## Dependencies" or "## Tools" that describes related content but does not match the expected terms (Stack, Tech, Language, Runtime, Framework).
- Documenting the tech stack only in `package.json` or `pyproject.toml` without a corresponding heading in the root instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Tech Stack

- Python 3.12, `uv` for dependency management
- `ruff` for linting, `pytest` for testing
~~~~

### Fail

~~~~markdown
# Project

## Getting Started

Install the dependencies and run the project.
We use Python and some testing tools.
~~~~

## Limitations

Checks for a heading containing "Stack", "Tech", "Language", "Runtime", or "Framework". Does not verify the section lists the actual technologies used.
