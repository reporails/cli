---
id: CODEX:S:0002
slug: skill-openai-yaml
title: "Skill OpenAI YAML"
category: structure
type: deterministic
severity: low
backed_by: []
match: {type: skill}
source: https://developers.openai.com/codex/skills
---

# Codex Skill Metadata Present

Codex skill directories SHOULD contain an `agents/openai.yaml` file with `display_name`, icon, and invocation policy fields. This metadata controls how the skill appears in the Codex UI and whether it can be triggered implicitly.

## Antipatterns

- **Missing metadata file.** Creating a skill directory with code and prompts but no `agents/openai.yaml`. The skill works but appears without a display name or icon in the Codex UI.
- **Implicit invocation disabled by default.** Omitting `allow_implicit_invocation: true` means the skill can only be triggered explicitly. If intended to be automatically triggered, this field must be set.
- **Generic display name.** Using `display_name: "Skill"` instead of a descriptive name like `"Code Review"`. The display name is what users see in the Codex interface.

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

