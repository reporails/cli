---
id: CORE:S:0014
slug: descriptive-filenames
title: Descriptive Filenames
category: structure
type: mechanical
severity: high
backed_by: [awesome-copilot-meta-instructions, instruction-limits-principles, microsoft-awesome-copilot-blog,
  rules-directory-mechanics, spec-writing-for-agents]
match: {type: scoped_rule}
---
# Descriptive Filenames

Scoped rule files must use lowercase kebab-case filenames ending in `.md`, `.yml`, or `.yaml`. Consistent naming lets developers predict file content from the filename and prevents platform-specific path issues.

## Antipatterns

- **CamelCase or UPPERCASE names** like `SelfCheck.md` or `SELF-CHECK.md` — the pattern requires all lowercase letters with hyphens as separators.
- **Underscores as separators** like `self_check.md` — the check enforces kebab-case (`-`), not snake_case (`_`).
- **Missing extension** like `self-check` with no `.md` suffix — the pattern requires a recognized extension.

## Pass / Fail

### Pass

~~~~markdown
.claude/rules/self-check.md
.claude/rules/testing-design.md
.claude/rules/no-unverified-claims.md
~~~~

### Fail

~~~~markdown
.claude/rules/SelfCheck.md
.claude/rules/testing_design.md
.claude/rules/NO-CLAIMS
~~~~

## Limitations

Checks that filenames are lowercase kebab-case. Does not evaluate whether the name accurately describes the file's content — only enforces naming conventions.
