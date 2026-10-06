---
id: COPILOT:S:0002
slug: setup-steps-defined
title: Setup Steps Defined
category: structure
type: deterministic
severity: low
backed_by: []
match: {type: coding_agent_setup}
source: https://docs.github.com/en/copilot/how-tos/agents/copilot-coding-agent/customizing-the-development-environment-for-copilot-coding-agent
---

# Setup Steps Defined

A Copilot Coding Agent project that ships `.github/workflows/copilot-setup-steps.yml` SHOULD define its job with the exact id `copilot-setup-steps`. The docs state the job "MUST be called `copilot-setup-steps` or it will not be picked up by Copilot" — any other job id in that file is silently ignored, and the agent starts working without the environment the workflow was meant to prepare.

## Antipatterns

- **Wrong job id.** Naming the job `setup`, `install`, or anything other than `copilot-setup-steps`. Copilot never runs it.
- **Setup steps only in prose.** Documenting "Run `npm install` first" in a Markdown instructions file instead of the workflow. Copilot's coding agent executes this specific workflow automatically; prose elsewhere requires the agent to interpret it and may be skipped.
- **Workflow not on the default branch.** The file only takes effect once it exists on the repository's default branch.

## Pass / Fail

### Pass

```yaml
name: "Copilot Setup Steps"
on:
  workflow_dispatch:
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
```

### Fail

```yaml
name: "Copilot Setup Steps"
on:
  workflow_dispatch:
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
```

## Limitations

Checks for the exact job id `copilot-setup-steps` in the workflow file. Does not validate the job's `steps:`, `permissions`, or other content.

