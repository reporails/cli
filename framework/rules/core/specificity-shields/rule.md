---
id: CORE:C:0050
slug: specificity-shields
title: "Specificity Shields Against Competition"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
---

# Specificity Shields Against Competition

Directives in prose-heavy files must name specific constructs to resist topic competition. A vague directive surrounded by prose on the same topic degrades severely, while a named directive holds compliance. The naming shield protects directives you want followed. It does not protect prohibitions: naming a forbidden construct anchors it instead of shielding it, so state prohibitions as abstract categories.

## Antipatterns

- Writing a generic directive in a file with extensive explanatory prose. "Use the formatter" in a file with paragraphs about formatting conventions gets overwhelmed by the surrounding content.
- Adding context paragraphs around a vague directive without naming constructs in the directive itself. The prose competes with the vague instruction and wins.
- Keeping instructions abstract in files that also contain documentation. Prose-heavy files demand more specific instructions, not less.

## Pass / Fail

### Pass

~~~~markdown
Code formatting uses `ruff format` with the config
in `pyproject.toml`. *Do not run a different formatter.*
~~~~

### Fail

~~~~markdown
We use a consistent code formatting approach across
the project. Follow the standard formatting rules.
Always format your code before committing.
~~~~

## Fix

In files with substantial prose, naming specific constructs is even more critical. Vague instructions in prose-heavy files get hit twice: once by being vague, again by being vulnerable to competition. Priority: name constructs first, then reduce surrounding prose.

## Limitations

Combines specificity measurement with prose density. May flag files where prose is intentionally kept for human readers — the diagnostic applies to model compliance, not human readability.
