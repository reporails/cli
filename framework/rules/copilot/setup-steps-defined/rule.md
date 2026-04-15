---
id: COPILOT:S:0002
slug: setup-steps-defined
title: Setup Steps Defined
category: structure
type: deterministic
severity: low
backed_by:
- copilot-coding-agent-best-practices
- copilot-coding-agent-results
- copilot-coding-agent-tasks
match: {type: main}
---

# Setup Steps Defined

Copilot Coding Agent projects SHOULD define a `steps:` array in their configuration to specify workspace setup commands. These steps run before the agent starts working — without them, the agent may fail on projects that require dependency installation, database setup, or build steps.

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

