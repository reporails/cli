---
id: CORE:S:0005
slug: identity-fields-in-frontmatter
title: "Identity Fields In Frontmatter"
category: structure
type: deterministic
severity: high
backed_by: []
match: {type: scoped_rule}
---

# Identity Fields In Frontmatter

Frontmatter must include identity fields (id, name, or slug) to uniquely identify the instruction file. Without an identity field, the file cannot be referenced, overridden, or tracked by other rules.

## Antipatterns

- **Frontmatter with only metadata fields**: A frontmatter block containing `globs:` and `description:` but no `id:`, `name:`, or `slug:` field. The check requires at least one identity key.
- **Identity field in body instead of frontmatter**: Writing `id: my-rule` in the markdown body rather than between `---` fences. The pattern matches anywhere in the file, but the rule intent is frontmatter placement.
- **Misspelled identity key**: Using `ID:` or `Slug:` — the check pattern is case-insensitive, so these pass. But using `identifier:` or `label:` instead of `id`, `name`, or `slug` will fail because only those three keywords are matched.

## Pass / Fail

### Pass

~~~~markdown
---
slug: my-rule
description: Enforces naming conventions
globs: ["src/**/*.py"]
---
~~~~

### Fail

~~~~markdown
---
description: Enforces naming conventions
globs: ["src/**/*.py"]
---
~~~~

## Limitations

Checks for identity-related frontmatter fields (`id`, `name`, `slug`). Does not validate whether the values are correct or unique.
