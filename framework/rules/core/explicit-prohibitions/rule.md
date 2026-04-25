---
id: CORE:C:0019
slug: explicit-prohibitions
title: Explicit Prohibitions
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, agents-md-impact-efficiency, builder-ai-instruction-best-practices,
  claude-code-issue-13579, claude-md-guide, claudemd-best-practices-backbone-yml-pattern,
  developer-context-cursor-study, enterprise-claude-usage, fowler-pushing-ai-autonomy,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, prompthub-cursor-rules-analysis,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {format: freeform}
---
# Explicit Prohibitions

Instruction files must contain at least one constraint atom — a sentence that tells the agent what NOT to do. Without explicit prohibitions, the agent defaults to its training priors, which may include destructive actions like force-pushing, deleting files, or modifying sensitive configurations.

## Antipatterns

- **Only positive directives** like "Use `ruff` for formatting" and "Run tests before committing" with no constraints — the check requires at least one sentence classified as a constraint (charge -1).
- **Soft preferences instead of prohibitions** like "Prefer not to modify the database" — hedged language does not register as a constraint atom.
- **Prohibitions only in comments or code blocks** like constraints inside `<!-- -->` or fenced blocks — the content query analyzes parsed instruction atoms, not raw text in non-prose regions.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for formatting and linting.
*Do NOT run `black` or manual formatting.*
NEVER modify `.env` files directly.
~~~~

### Fail

~~~~markdown
Use `ruff` for formatting and linting.
Run `uv run pytest` before committing.
Follow the project conventions.
~~~~

## Limitations

Checks for at least one constraint atom (NEVER, MUST NOT, DO NOT). Does not evaluate whether the prohibitions cover the project's actual risk areas.
