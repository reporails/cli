---
id: CORE:S:0013
slug: scope-fields-in-frontmatter
title: Scope Fields In Frontmatter
category: structure
type: deterministic
severity: medium
backed_by: [awesome-copilot-meta-instructions, rules-directory-mechanics]
match: {type: scoped_rule}
---

# Scope Fields In Frontmatter

Scoped instruction files must declare their scope boundary in frontmatter using `scope:`, `globs:`, or `applies_to:` fields. Without a declared scope, the file's targeting is ambiguous and the agent cannot determine which files the instructions apply to.

## Antipatterns

- Describing scope in prose ("This rule applies to Python files") without a frontmatter field. The check looks for `scope:`, `globs:`, or `applies_to:` key-value declarations, not prose descriptions.
- Using a non-standard field name like `targets:` or `files:`. The pattern matches `scope`, `globs`, and `applies_to` specifically.
- Omitting scope fields entirely because the file is "obviously" scoped by its directory path. The rule requires explicit declaration regardless of directory placement.

## Pass / Fail

### Pass

~~~~markdown
---
globs: "src/**/*.py"
---
# Python Style

Use `ruff` for formatting.
~~~~

### Fail

~~~~markdown
---
title: Python Style
---
# Python Style

Use `ruff` for formatting Python files.
~~~~

## Threshold

The check is gated by file size: rules below 30 lines do not fire. Tiny rules consumed in one narrow context get little benefit from explicit scope fields, and the noise drowns out genuine missing-scope cases on load-bearing rules.

Override the threshold per project in `.ails/config.yml`:

```yaml
rule_thresholds:
  CORE:S:0013:
    min_lines: 50
```

Setting `min_lines: 0` removes the gate and restores fire-on-every-rule behavior.

## Limitations

Checks for scope-related frontmatter fields (`scope`, `globs`, `applies_to`). Does not validate whether the declared scope is correct.
