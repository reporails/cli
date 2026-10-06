---
id: CORE:G:0005
slug: permission-config-denies-sensitive
title: Permission Config Denies Sensitive
category: governance
type: mechanical
enforcement_required: true
enforcement_mechanism: permission
severity: medium
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/settings
---
# Permission Config Denies Sensitive

A configuration file must declare a non-empty `"permissions.deny"` list. Without an explicit denial, the agent may read or write secrets, credentials, and private keys.

## Antipatterns

- **Config file with only positive permissions.** A settings file that grants tool access but declares no `"deny"` entries at all. The check requires at least one denied pattern.
- **Empty deny array.** Declaring `"deny": []` — the key exists but denies nothing, which behaves the same as omitting it.
- **Mentioning sensitive files in prose without a denial.** Describing that `.env` files exist in a comment or doc is not a denial. The check reads the config's own `"deny"` list, not prose about it.
- **Relying on `.gitignore` alone.** Excluding sensitive files from version control does not prevent the agent from reading them at runtime. The config must contain an explicit denial entry.

## Pass / Fail

### Pass

```json
{
  "permissions": {
    "deny": ["Read(.env)", "Read(credentials.yml)", "Read(*.pem)"]
  }
}
```

### Fail

```json
{
  "permissions": {
    "deny": []
  }
}
```

## Limitations

Checks for a non-empty `"deny"` list. Does not verify the denied patterns actually cover the project's own secrets and credentials.
