---
id: CORE:C:0013
slug: project-description-present
title: Project Description Present
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claude-md-guide, developer-context-cursor-study,
  evaluating-agents-md, instruction-limits-principles, microsoft-awesome-copilot-blog,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, spec-writing-for-agents]
match: {type: main}
---
# Project Description Present

The root instruction file must describe the project — what it does and who it's for. This anchors the agent's understanding of context and purpose.

## Antipatterns

- **Jumping straight to commands.** A root file that starts with `## Commands` and lists CLI invocations but never describes what the project is. The check looks for a heading matching "Description", "About", or "Overview".
- **Description buried under a non-matching heading.** Writing the project description under `## Background` or `## Context` does not match the expected heading terms. Use "Description", "About", or "Overview" as the heading.
- **Project name as the only heading.** A single `# My Project` heading with commands underneath does not satisfy the check. The file needs a dedicated description section under one of the matching heading terms.

## Pass / Fail

### Pass

~~~~markdown
# Reporails CLI

## Overview

AI instruction validator for coding agents.

## Commands

- `uv run ails check .` — validate instruction files
~~~~

### Fail

~~~~markdown
# Reporails CLI

## Commands

- `uv run ails check .` — validate instruction files
- `uv run ails heal` — interactive auto-fix
~~~~

## Limitations

Checks for a heading containing "Description", "About", or "Overview". Does not evaluate whether the description accurately represents the project.
