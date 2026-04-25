---
id: CORE:C:0010
slug: build-and-test-commands
title: Build And Test Commands
category: coherence
type: mechanical
severity: medium
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, builder-ai-instruction-best-practices, claude-md-guide,
  claude-md-optimization-study, developer-context-cursor-study, dometrain-claude-md-guide,
  evaluating-agents-md, fowler-pushing-ai-autonomy, instruction-limits-principles,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, prompthub-cursor-rules-analysis,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Build And Test Commands

The instruction file must include build and test commands that the agent can run. Without these, the agent can't verify its own changes work correctly.

## Antipatterns

- Providing build commands in prose ("you can build by running the makefile") without a heading containing "Commands", "Build", "Testing", or "Setup". The check matches headings, not body text.
- Using a heading like "## Development" or "## Usage" that does not contain any of the matched terms. The heading must include one of the specific keywords.
- Documenting commands only in a README or separate file. The check targets the main instruction file.

## Pass / Fail

### Pass

~~~~markdown
# MyProject

## Commands

- `npm install` -- install dependencies
- `npm test` -- run test suite
~~~~

### Fail

~~~~markdown
# MyProject

## Conventions

Use ESLint for linting.
Prefer functional components.
~~~~

## Limitations

Checks for a heading containing "Commands", "Build", "Testing", or "Setup". Does not verify the section contains runnable commands.
