---
id: CORE:C:0013
slug: project-description-present
title: Project Description Present
category: coherence
type: mechanical
severity: medium
backed_by: [agent-readmes-empirical-study, agentic-coding-adoption-github, agents-md-impact-efficiency,
  awesome-copilot-meta-instructions, claude-md-guide, developer-context-cursor-study,
  evaluating-agents-md, instruction-limits-principles, microsoft-awesome-copilot-blog,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, spec-writing-for-agents]
match: {type: main}
---
# Project Description Present

The root instruction file must describe the project — what it does and who it's for. This anchors the agent's understanding of context and purpose.

## Antipatterns

- **Jumping straight to commands.** A root file that starts with `## Commands` and lists CLI invocations but never describes what the project is. The check looks for a heading matching "Description", "About", or "Overview", or a description under the title.
- **Description buried under a non-matching heading.** Writing the project description under `## Background` or `## Context`, after the first section, does not count. Put it directly under the title, or use "Description", "About", or "Overview" as the heading.
- **Project name with nothing under it.** A `# My Project` title followed straight by commands or instructions does not describe the project. Add a sentence under the title that says what the project is and who it is for.

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
- `uv run ails check --heal` — interactive auto-fix
~~~~

## Limitations

Accepts a heading containing "Description", "About", or "Overview", or a descriptive paragraph, blockquote, or list of five or more words under the title, before the first section heading and before the first instruction. An instruction-shaped sentence does not count as a description. Does not evaluate whether the description accurately represents the project.
