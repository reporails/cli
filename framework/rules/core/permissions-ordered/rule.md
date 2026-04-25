---
id: CORE:G:0003
slug: permissions-ordered
title: Permissions Ordered
category: governance
type: deterministic
severity: medium
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/settings
---

# Permissions Ordered

Permission declarations in agent configuration must follow a deterministic order — deny rules before allow rules, specific patterns before broad wildcards. First-match-wins semantics in permission evaluation mean ordering determines which rule fires. A broad `allow: Bash(*)` before a specific `deny: Bash(rm -rf *)` silently permits the dangerous command.

## Antipatterns

- **Broad allow before specific deny.** Placing `"Bash(*)"` in the allow list while a deny rule for destructive commands exists later. The allow matches first.
- **Wildcard permissions without narrowing.** Using `"Read(**)"`, `"Write(**)"`, `"Bash(*)"` without any deny entries to constrain the broad access.
- **No deny section at all.** Omitting the deny list entirely when sensitive file patterns (`.env`, credentials) should be restricted.

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
  "permissions": {
    "allow": ["Bash(*)", "Read(**)", "Write(**)"]
  }
}
```

## Limitations

Checks for the presence of permission structure with both restrictive and permissive entries. Does not evaluate the semantic ordering of individual permission patterns or verify that deny rules are actually more specific than allow rules.
