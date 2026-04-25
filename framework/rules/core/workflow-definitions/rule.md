---
id: CORE:C:0007
slug: workflow-definitions
title: Workflow Definitions
category: coherence
type: mechanical
severity: medium
backed_by: [advanced-context-engineering, agent-readmes-empirical-study, agentic-coding-adoption-github,
  agents-md-impact-efficiency, claude-code-issue-13579, claudemd-best-practices-mermaid-for-workflows,
  developer-context-cursor-study, dometrain-claude-md-guide, enterprise-claude-usage,
  flowbench-workflow-format-benchmark, fowler-context-engineering-agents, fowler-pushing-ai-autonomy,
  microsoft-awesome-copilot-blog, openai-community-agents-md-optimization, osmani-ai-coding-workflow,
  prompthub-cursor-rules-analysis, sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Workflow Definitions

The instruction file must contain a heading matching workflow terms (Workflow, Process, Pipeline, or Steps). Defining repeatable workflows with ordered steps helps the agent follow consistent processes for common tasks.

## Antipatterns

- Listing commands without a heading that matches workflow terms. The check requires a heading containing Workflow, Process, Pipeline, or Steps -- not just numbered lists of commands.
- Using a heading like "## How To" or "## Procedures" that describes workflow content but does not match the expected terms.
- Documenting workflows only in external runbooks or CI configuration without a corresponding section in the instruction file.

## Pass / Fail

### Pass

~~~~markdown
# Project

## Workflow

1. Run `uv run poe qa_fast` for pre-commit checks.
2. Create a PR with `gh pr create`.
3. Wait for CI to pass before merging.
~~~~

### Fail

~~~~markdown
# Project

## Setup

Install with `uv sync` and start developing.
~~~~

## Limitations

Checks for a heading containing "Workflow", "Process", "Pipeline", or "Steps". Does not verify the section defines repeatable processes with ordered steps.
