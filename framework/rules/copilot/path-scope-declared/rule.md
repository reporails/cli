---
id: COPILOT:S:0001
slug: path-scope-declared
title: Path Scope Declared
category: structure
type: mechanical
severity: high
backed_by: [awesome-copilot-meta-instructions]
match: {type: rules, format: [frontmatter, freeform]}
supersedes: CORE:S:0038
source: https://code.visualstudio.com/docs/copilot/customization/custom-instructions
---

# Path Scope Declared

A scoped instructions file MUST declare its file-pattern filter in frontmatter. `.github/instructions/**/*.instructions.md` files use `applyTo`; VS Code Copilot also reads `.claude/rules/**/*.md` for cross-agent compatibility, and for those files the VS Code docs say to keep Claude's own `paths` key instead of `applyTo`. Without a scope key in the file type that requires one, Copilot applies the instructions globally, which defeats the purpose of scoping and can surface irrelevant guidance in unrelated contexts.

## Antipatterns

- **`.instructions.md` without `applyTo`.** Creating a `.github/instructions/python.instructions.md` intended for Python files but not adding `applyTo: "**/*.py"`. Copilot applies the instructions to all files, including JavaScript and YAML.
- **Using `globs` or `paths` in `.instructions.md`.** Copilot only recognizes `applyTo` in this file family; `globs` (Cursor) and `paths` (Claude, outside `.claude/rules/`) have no effect there.
- **`applyTo` in the wrong file.** Adding `applyTo` to the root-level `.github/copilot-instructions.md` instead of a scoped `.instructions.md` variant. The root file applies globally by design.

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

A `.claude/rules/*.md` file scoped with `paths:` also passes — that key is correct for this file family and draws no finding.

## Limitations

Does not verify that the `applyTo` pattern targets the file types the author intended — only that the glob resolves to at least one file. Cannot detect overly broad patterns like `applyTo: "**/*"` that effectively disable scoping.

