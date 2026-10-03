---
id: CORE:G:0009
slug: subagent-system-prompt-no-secrets
title: Subagent System Prompt No Secrets
category: governance
type: deterministic
severity: high
requires_capability: agents
backed_by: []
match: {type: agents, format: [frontmatter, freeform]}
source: https://code.claude.com/docs/en/sub-agents
---

# Subagent System Prompt No Secrets

A subagent definition (`.claude/agents/<name>.md`) must not embed a credential, API key, password, or private key in its frontmatter or system-prompt body. A subagent file is committed instruction text loaded into an agent's context; a secret written there leaks into version control and into every session that dispatches the subagent. Reference secrets through environment variables or a secret store the tool reads at runtime, never as a literal in the prompt.

## Antipatterns

- **Baking an API key into the prompt.** Writing `Use api_key = "sk-live-..."` in the body so the subagent "has" the credential — the key is now in git history and in context on every dispatch.
- **A private key block in the file.** Pasting a `-----BEGIN PRIVATE KEY-----` block into the agent definition.

## Pass / Fail

### Pass

```markdown
---
name: deployer
description: Use when deploying the service.
---
Read the deploy token from the `DEPLOY_TOKEN` environment variable before calling the API.
```

### Fail

```markdown
---
name: deployer
description: Use when deploying the service.
---
Authenticate with api_key = "sk-live-4eC39HqLyjWDarjtT1zdp7dc".
```

## Limitations

Matches common credential shapes (password / api-key assignments, `-----BEGIN` key blocks, `secret_key` assignments). A secret in an unusual format can pass; a benign string in a credential shape can flag.
