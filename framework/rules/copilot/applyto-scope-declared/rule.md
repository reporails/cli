---
id: COPILOT:S:0001
slug: applyto-scope-declared
title: ApplyTo Scope Declared
category: structure
type: mechanical
severity: high
backed_by: [awesome-copilot-meta-instructions]
match: {type: scoped_rule}
supersedes: CORE:S:0038
source: https://code.visualstudio.com/docs/copilot/customization/custom-instructions
---

# ApplyTo Scope Declared

Scoped `.github/copilot-instructions.md` files MUST include an `applyTo` field in their YAML frontmatter to declare which file patterns the instructions target. Without `applyTo`, Copilot applies the instructions globally, which defeats the purpose of scoped instruction files and can cause irrelevant guidance to appear in unrelated contexts.

## Antipatterns

- **Scoped file without `applyTo`.** Creating a `.github/copilot-instructions.md` intended for Python files but not adding `applyTo: "**/*.py"`. Copilot applies the instructions to all files, including JavaScript and YAML.
- **Using `globs` or `paths` instead of `applyTo`.** These keys work for Claude Code and Cursor respectively, but Copilot only recognizes `applyTo`.
- **`applyTo` in the wrong file.** Adding `applyTo` to the root-level instructions file instead of a scoped variant. The root file applies globally by design.

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

Does not verify that the `applyTo` pattern targets the file types the author intended — only that the glob resolves to at least one file. Cannot detect overly broad patterns like `applyTo: "**/*"` that effectively disable scoping.

