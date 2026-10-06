---
id: CORE:S:0017
slug: self-contained-skills
title: Self Contained Skills
category: structure
type: mechanical
severity: low
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents, fowler-pushing-ai-autonomy,
  microsoft-awesome-copilot-blog, osmani-ai-coding-workflow]
match: {type: skills, format: [frontmatter, freeform]}
---
# Self Contained Skills

Skill files should carry at least one structural heading — Input, Process, Output, Constraints, or an equivalent (Steps, Workflow, Prerequisites, Requirements, Result, Limitations) — so the skill is scannable and gives the agent what it needs without hunting through other files. The skill file format itself mandates no fixed section set; this rule nudges toward some structure, it does not require a specific four-heading layout.

## Antipatterns

- Including workflow steps in prose with no structural heading at all. The check looks for at least one recognized heading, not just content that covers those concerns.
- Using a heading name outside the recognized set. The check accepts a broad set — Input, Process, Output, Constraints, Steps, Workflow, Prerequisites, Requirements, Result, Limitations — so any of these satisfies it; a wholly idiosyncratic heading (e.g. "Notes") does not.
- Splitting the skill's structure across multiple files so the entry-point skill file carries no structural heading of its own. The check reads the single skill entry-point file.

## Pass / Fail

### Pass

~~~~markdown
# Deploy Skill

## Input
- Branch name, target environment

## Process
1. Run `uv run poe qa`. 2. Push to remote.

## Output
- Deployment URL printed to stdout

## Constraints
NEVER deploy without passing QA.
~~~~

### Fail

~~~~markdown
# Deploy Skill

Push the branch and deploy it.
Check the deployment URL afterward.
~~~~

## Limitations

Checks for at least one heading from the recognized set (Input, Process, Output, Constraints, Steps, Workflow, Prerequisites, Requirements, Result, Limitations). Does not verify each section is complete or that the skill is genuinely self-contained.
