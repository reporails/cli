---
id: CORE:C:0033
slug: architecture-overview-present
title: Architecture Overview Present
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claudemd-best-practices-backbone-yml-pattern,
  developer-context-cursor-study, dometrain-claude-md-guide, evaluating-agents-md,
  fowler-pushing-ai-autonomy, osmani-ai-coding-workflow, sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Architecture Overview Present

The root instruction file must describe the project's architecture. The agent needs to know where major components live to navigate the codebase and make informed changes.

## Antipatterns

- Describing the architecture in prose paragraphs without a heading that contains "Architecture", "Structure", or "Layout". The check looks for a matching heading, not for architectural content buried in other sections.
- Using a heading like "## Overview" or "## Design" that does not contain any of the matched terms. Close synonyms do not satisfy the heading keyword check.
- Placing the architecture section in a separate file without any mention in the main instruction file. The check runs against the main file only.

## Pass / Fail

### Pass

~~~~markdown
# MyApp

Backend API for widget management.

## Architecture

src/ contains domain logic.
tests/ contains pytest suites.
~~~~

### Fail

~~~~markdown
# MyApp

Backend API for widget management.

## Commands

Run `make build` to compile.
~~~~

## Limitations

Checks for a heading containing "Architecture", "Structure", or "Layout". Does not evaluate whether the content under that heading actually describes the system architecture.
