---
id: CODEX:S:0002
slug: skill-openai-yaml
title: "Skill OpenAI YAML"
category: structure
type: deterministic
severity: low
backed_by: []
match: {type: skills}
source: https://learn.chatgpt.com/docs/build-skills
---

# Codex Skill Metadata Present

Codex reads optional per-skill metadata — a display name, an icon, and an invocation policy — from a settings file in the skill directory. Without it, the skill shows with no name or icon in the Codex UI, and cannot be triggered implicitly.

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

