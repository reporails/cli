---
id: CLAUDE:S:0009
slug: rule-snippet-length
title: "Rule File Length Limit"
category: structure
type: mechanical
severity: medium
match: {type: scoped_rule}
---

# Rule File Length Limit

Keep `.claude/rules/*.md` files under 100 lines. Long rule files compete for attention with other context. Each rule file should address one topic with focused instructions.

## Limitations

Counts total lines including frontmatter, headings, and blank lines. Files just over the threshold may be acceptable if the content is dense and focused.
