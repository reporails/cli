---
id: CORE:E:0006
slug: italic-constraints
title: "Italic Constraints"
category: efficiency
type: mechanical
severity: low
match: {format: [freeform, frontmatter]}
surface_mutations:
  memory: {applies: false}
---

# Italic Constraints

Prohibitions should be wrapped entirely in `*italic*` markdown. Full-sentence italic visually marks a prohibition, separating it from the directive and the reasoning that precede it.

## Antipatterns

- **Partial italic on negation only**: "*Do NOT* modify `checks.yml` directly." — only the negation keyword is italicized, not the full prohibition. The check requires the entire prohibition to be wrapped in `*...*`.
- **Bold instead of italic**: "**Do NOT modify checks.yml directly.**" — bold is not the same signal as italic. The check looks for single `*...*` markers, not `**...**`.
- **No formatting on constraint**: "Do NOT modify checks.yml directly." — an unformatted prohibition is structurally indistinguishable from surrounding prose. The check flags prohibitions whose raw text lacks full italic wrapping.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for all formatting in `src/`.
*Do not run a formatter other than `ruff`.*
~~~~

### Fail

~~~~markdown
Use `ruff` for all formatting in `src/`.
Do NOT run `black` or apply manual formatting.
~~~~

## Limitations

Detects prohibitions whose raw markdown text is not fully wrapped in single `*...*` markers. Runs on instruction files (freeform or frontmatter markdown); agent configuration files such as `config.toml` are not checked. Does not evaluate whether the italic wrapping improves compliance for the specific instruction — the check is structural, not semantic.
