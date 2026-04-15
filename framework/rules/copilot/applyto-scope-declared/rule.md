---
id: COPILOT:S:0001
slug: applyto-scope-declared
title: ApplyTo Scope Declared
category: structure
type: mechanical
severity: high
backed_by:
- awesome-copilot-meta-instructions
- copilot-ai-best-practices-vscode
- copilot-coding-agent-best-practices
- copilot-coding-agent-results
- copilot-coding-agent-tasks
- copilot-custom-instructions
- copilot-custom-instructions-vscode
match: {type: scoped_rule}
---

# ApplyTo Scope Declared

Scoped `.github/copilot-instructions.md` files MUST include an `applyTo` field in their YAML frontmatter to declare which file patterns the instructions target. Without `applyTo`, Copilot applies the instructions globally, which defeats the purpose of scoped instruction files and can cause irrelevant guidance to appear in unrelated contexts.

## Pass / Fail

### Pass

```yaml
---
applyTo: "**/*.py"
---

Use type hints on all function signatures.
```

### Fail

```markdown
Use type hints on all function signatures.
```

## Limitations

Checks for the presence of an `applyTo` frontmatter key. Does not validate that the glob pattern is syntactically correct or matches actual project files.

