---
id: CORE:C:0057
slug: skill-invocation-reachable
title: Skill Invocation Reachable
category: coherence
type: deterministic
severity: medium
requires_capability: skills
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://code.claude.com/docs/en/skills
---

# Skill Invocation Reachable

A skill must stay invocable by someone. Two `SKILL.md` frontmatter gates control who can invoke it: `disable-model-invocation: true` stops the model from auto-invoking (only the user can, via `/name`), and `user-invocable: false` hides it from the `/` menu (only the model can invoke it). Setting both makes the skill unreachable — the model cannot invoke it and neither can the user, so the skill is dead config that loads for no path. Set at most one of the two gates so at least one invoker remains.

## Antipatterns

- **Both gates closed.** Declaring `disable-model-invocation: true` and `user-invocable: false` together, on the assumption each independently narrows access — together they remove every invoker and the skill can never run.

## Pass / Fail

### Pass

```yaml
---
description: Deploy the service to production.
disable-model-invocation: true
---
```

### Fail

```yaml
---
description: Deploy the service to production.
disable-model-invocation: true
user-invocable: false
---
```

## Limitations

Forward-guards a specific dead-config contradiction: both invocation gates set to their access-removing values in one `SKILL.md`. The combination is rare in practice — the check is a cheap structural guard, not a high-frequency finding. It does not evaluate `skillOverrides` from settings, which can change invocability out-of-band.
