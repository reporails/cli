---
id: CODEX:G:0001
slug: permissions-ordered
title: Permission Config Declared
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: permission
severity: medium
backed_by: []
match: {type: config}
supersedes: CORE:G:0003
source: https://learn.chatgpt.com/docs/config-file/config-advanced
---

# Permission Config Declared

Codex configuration must declare its access policy. Codex has no `permissions` block; it controls access through `approval_policy` (when Codex asks before acting) and `sandbox_mode` (what Codex may touch). A `config.toml` that sets neither leaves access entirely to the host defaults, so nothing in the project records what the agent may do. Setting either key makes the access policy visible and reviewable in the repository.

This is the Codex form of `CORE:G:0003`; Claude and Gemini settings files keep the `permissions` block form.

## Antipatterns

- **No access setting at all.** A `config.toml` that sets neither `approval_policy` nor `sandbox_mode`, deferring every access decision to the defaults.
- **Access policy kept out of the repository.** Relying on user-level settings for project access rules, so the committed config records nothing a reviewer can inspect.

## Pass / Fail

### Pass

```toml
approval_policy = "on-request"
sandbox_mode = "workspace-write"
```

### Fail

```toml
model = "your-model"
```

## Limitations

Checks only that `approval_policy` or `sandbox_mode` is set in the configuration. Does not judge whether the value is strict or loose; a sandbox switched off is reported separately by `CODEX:G:0002`.
