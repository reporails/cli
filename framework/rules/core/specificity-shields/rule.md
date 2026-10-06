---
id: CORE:C:0050
slug: specificity-shields
title: "Specificity Shields Against Competition"
category: coherence
type: mechanical
execution: server
severity: critical
match: {}
---

# Specificity Shields Against Competition

Directives in prose-heavy files must name specific constructs to resist topic competition. A vague directive surrounded by prose on the same topic can degrade, while a named directive tends to hold compliance. The naming shield protects directives you want followed. It does not protect prohibitions: naming a forbidden construct anchors it instead of shielding it, so state prohibitions as abstract categories.

## Antipatterns

- Writing a generic directive in a file with extensive explanatory prose. "Use the formatter" in a file with paragraphs about formatting conventions can get overwhelmed by the surrounding content.
- Adding context paragraphs around a vague directive without naming constructs in the directive itself. The prose can compete with the vague instruction and win.
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

## Limitations

Combines specificity measurement with prose density. May flag files where prose is intentionally kept for human readers — the diagnostic applies to model compliance, not human readability. Fires while the same-topic context around a vague instruction is still approaching the dilution point; past that point the finding is reported as Content Dilution (CORE:C:0041).

How much same-topic prose weakens an instruction depends on the model. Treat the finding as a prompt to review the prose, not as an instruction to delete it.
