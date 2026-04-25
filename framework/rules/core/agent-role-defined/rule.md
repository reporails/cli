---
id: CORE:C:0014
slug: agent-role-defined
title: Agent Role Defined
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, developer-context-cursor-study, fowler-pushing-ai-autonomy,
  microsoft-awesome-copilot-blog, openai-community-agents-md-optimization, osmani-ai-coding-workflow,
  spec-writing-for-agents]
match: {type: main}
---
# Agent Role Defined

The instruction file must define the agent's role and primary function. Without a clear identity, the agent defaults to generic behavior that doesn't match the project's needs.

## Antipatterns

- Jumping straight into commands and conventions without stating what the agent is or does. The check looks for a role definition -- a statement of identity or expertise -- not just operational instructions.
- Writing "This file contains project instructions" as the opening line. That describes the file, not the agent's role. The check needs language that defines the agent's function or domain.
- Assuming the project name implies the role. A heading like "# MyApp" does not tell the agent what it is responsible for.

## Pass / Fail

### Pass

~~~~markdown
# Reporails CLI

AI instruction validator -- validates instruction files
against mechanical and deterministic rules.
~~~~

### Fail

~~~~markdown
# Reporails CLI

## Commands

- `uv run ails check .`
- `uv run poe qa`
~~~~

## Limitations

Checks for a role definition atom (explicit role assignment or "you are" pattern). Does not evaluate whether the defined role is appropriate for the project.
