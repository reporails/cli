---
id: COPILOT:S:0002
slug: setup-steps-defined
title: Setup Steps Defined
category: structure
type: deterministic
severity: low
backed_by: []
match: {type: main}
source: https://docs.github.com/copilot/how-tos/agents/copilot-coding-agent/best-practices-for-using-copilot-to-work-on-tasks
---

# Setup Steps Defined

Copilot Coding Agent projects SHOULD define a `steps:` array in their configuration to specify workspace setup commands. These steps run before the agent starts working — without them, the agent may fail on projects that require dependency installation, database setup, or build steps.

## Antipatterns

- **Setup in prose, not in `steps:`.** Writing "Run `npm install` first" in natural language instead of defining a structured `steps:` array. Copilot Coding Agent executes the `steps:` array automatically — prose instructions require the agent to interpret and may be skipped.
- **Missing build step.** Defining `steps:` with only `npm install` but omitting `npm run build`. The agent starts working on a project that isn't built, leading to false failures.
- **Steps without names.** Defining command entries without `name:` fields. Names appear in the agent's execution log and help diagnose which setup step failed.

## Pass / Fail

### Pass

```yaml
steps:
  - name: install
    command: npm install
  - name: build
    command: npm run build
```

### Fail

```markdown
# Project Setup

Run npm install to get started.
```

## Limitations

Checks for the presence of a `steps:` key in the file. Does not validate that individual step entries have valid `name` and `command` fields.

