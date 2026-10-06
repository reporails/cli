---
id: CORE:G:0003
slug: permissions-ordered
title: Permission Config Declared
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: permission
severity: medium
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/settings
---

# Permission Config Declared

Agent configuration must declare an explicit permission block. A config with no `permissions` section leaves access entirely to the host defaults, so nothing in the project records which tools and paths the agent may touch. Declaring the block — even a minimal one — makes the access policy visible and reviewable in the repository.

## Antipatterns

- **No permission block at all.** A settings file that omits the `permissions` key entirely, deferring every access decision to the host runtime's defaults.
- **Access policy kept out of the repository.** Relying on user-level or machine-level settings for project access rules, so the committed config records nothing a reviewer can inspect.

## Pass / Fail

### Pass

```json
{
  "permissions": {
    "deny": ["Read(.env*)", "Write(credentials*)"],
    "allow": ["Read(**)", "Write(src/**)"]
  }
}
```

### Fail

```json
{
  "settings": {}
}
```

## Limitations

Checks only that a `permissions` block is present in the configuration. Does not evaluate the order of individual permission entries, whether deny rules precede allow rules, or whether any given pattern is broad or narrow. Confirming that sensitive paths are actually denied is covered separately by `CORE:G:0005`.
