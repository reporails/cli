---
id: CORE:S:0006
slug: frontmatter-block-present
title: Frontmatter Block Present
category: structure
type: deterministic
severity: high
backed_by: [agent-readmes-empirical-study, awesome-copilot-meta-instructions, rules-directory-mechanics]
match: {type: scoped_rule}
---

# Frontmatter Block Present

Scoped rule files must begin with a `---` YAML frontmatter delimiter as the very first line. The frontmatter block provides metadata like `globs` and `description` that controls how the agent discovers and loads the rule file.

## Antipatterns

- **Leading blank line before frontmatter** like a newline then `---` — the pattern `\A---` requires the delimiter at byte position zero with no preceding whitespace or blank lines.
- **Using a different delimiter** like `~~~` or `===` — the check specifically matches `---` followed by a newline.
- **Frontmatter comment before the delimiter** like `<!-- metadata -->` then `---` — any content before the opening `---` causes the pattern to fail.

## Pass / Fail

### Pass

~~~~markdown
---
globs: "src/**/*.py"
description: Python source conventions
---
# Source Conventions
~~~~

### Fail

~~~~markdown

---
globs: "src/**/*.py"
---
# Source Conventions
(leading blank line before ---)
~~~~

## Limitations

Checks for YAML frontmatter opening delimiter at the start of the file. Does not validate frontmatter content or schema compliance.
