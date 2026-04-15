---
id: CORE:S:0017
slug: self-contained-skills
title: "Self Contained Skills"
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: skill}
---
# Self Contained Skills

Skill files must include headings matching Input, Process, Output, and Constraints. A self-contained skill gives the agent everything it needs to execute the task without hunting through other files.

## Antipatterns

- Including workflow steps in prose without using a "Process" or "Input" heading. The check requires headings that match the expected terms, not just content that covers those concerns.
- Using non-standard heading names like "Prerequisites" instead of "Input", or "Steps" instead of "Process". The check matches specific terms.
- Splitting skill sections across multiple files. The check expects all required sections within the single skill entry point file.

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

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
