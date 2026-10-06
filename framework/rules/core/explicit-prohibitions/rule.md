---
id: CORE:C:0019
slug: explicit-prohibitions
title: Explicit Prohibitions
category: coherence
type: mechanical
severity: medium
backed_by: [agent-readmes-empirical-study, agents-md-impact-efficiency, builder-ai-instruction-best-practices,
  claude-code-issue-13579, claude-md-guide, claudemd-best-practices-backbone-yml-pattern,
  developer-context-cursor-study, enterprise-claude-usage, fowler-pushing-ai-autonomy,
  openai-community-agents-md-optimization, osmani-ai-coding-workflow, prompthub-cursor-rules-analysis,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {type: [main, override, agents_md, legacy_cursorrules, cross_read, system_prompt], cardinality: [singleton, chain]}
---
# Explicit Prohibitions

The agent's main instruction file must contain at least one prohibition — a sentence that tells the agent what NOT to do. Without explicit prohibitions, the agent defaults to its training priors, which may include destructive actions like force-pushing, deleting files, or modifying sensitive configurations.

## Antipatterns

- **Only positive directives** like "Use `ruff` for formatting" and "Run tests before committing" with no constraints — the check requires at least one sentence stating what not to do.
- **Soft preferences instead of prohibitions** like "Prefer not to modify the database" — hedged language does not register as a prohibition.
- **Prohibitions the checker cannot see** — a constraint written only inside an HTML comment (`<!-- -->`) or inside a fenced block that reads as code (a block tagged with a language, or one whose body parses as code or a diagram). The check counts prohibitions in parsed prose and in fenced blocks that read as instructions, but not comment interiors or code blocks, so a prohibition placed only there does not register. State at least one prohibition in prose. This is a limit of what the checker parses, not a claim such a prohibition is ineffective.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for formatting and linting.
*Do not run a formatter other than `ruff`.*
Never modify environment or credential files.
~~~~

### Fail

~~~~markdown
Use `ruff` for formatting and linting.
Run `uv run pytest` before committing.
Follow the project conventions.
~~~~

## Limitations

Checks for at least one prohibition (NEVER, MUST NOT, DO NOT) in parsed prose or in a fenced block that reads as an instruction. A prohibition inside an HTML comment, or inside a block that reads as code, falls outside the parser's scope and is not counted — a resolution limit of the analysis, not a judgment on its effectiveness. Does not evaluate whether the prohibitions cover the project's actual risk areas.
