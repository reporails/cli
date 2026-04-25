---
id: CORE:D:0001
slug: directive-density
title: Directive Density
category: direction
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, awesome-copilot-meta-instructions, claude-md-guide,
  developer-context-cursor-study, fowler-pushing-ai-autonomy, openai-community-agents-md-optimization,
  osmani-ai-coding-workflow, spec-writing-for-agents]
match: {format: freeform}
see_also: []
---
# Directive Density

Instruction files must contain at least one directive atom — a sentence that tells the agent what to do using imperative or absolute modality. Files with only descriptive prose and no actionable directives have no behavioral effect on the agent.

## Antipatterns

- **Pure description** like "This project uses Python and pytest for testing" with no imperatives — descriptive sentences explain context but give no actionable direction.
- **Passive voice throughout** like "Tests should be considered before changes are made" — passive hedging does not register as a directive to the agent.
- **Only headings and structure** like a file with `## Testing`, `## Deployment` headers but no imperative sentences underneath — headings organize content but are not directives.

## Pass / Fail

### Pass

~~~~markdown
# Testing
Run `uv run pytest tests/` before submitting changes.
Use `ruff` for formatting and linting.
~~~~

### Fail

~~~~markdown
# Testing
This project has a test suite located in the tests/ directory.
The project uses pytest as its test framework.
~~~~

## Limitations

Checks that the file contains directive instructions. Does not evaluate the content or specificity of those instructions.
