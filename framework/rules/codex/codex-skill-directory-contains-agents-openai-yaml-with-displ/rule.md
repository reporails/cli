---
id: CODEX:S:0002
slug: codex-skill-directory-contains-agents-openai-yaml-with-displ
title: Codex Skill Directory Contains Agents/Openai.Yaml With Display Name, 
  Icon, And Policy Fields
category: structure
type: deterministic
severity: low
backed_by:
- codex-skills-guide
match: {type: skill}
---

# Codex Skill Metadata Present

Codex skill directories SHOULD contain an `agents/openai.yaml` file with `display_name`, icon, and invocation policy fields. This metadata controls how the skill appears in the Codex UI and whether it can be triggered implicitly.

## Pass / Fail

### Pass

```yaml
# agents/openai.yaml
display_name: Code Review
brand_color: "#4A90D9"
allow_implicit_invocation: true
```

### Fail

```
agents/
└── (no openai.yaml)
```

## Limitations

Checks for the presence of metadata keywords (`display_name`, `allow_implicit_invocation`, `brand_color`). Does not validate YAML syntax or field values.

