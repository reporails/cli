---
id: CORE:C:0051
slug: compound-weakness
title: "Compound Weakness"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Compound Weakness

Multiple weaknesses in the same instruction compound — an instruction that is hedged AND abstract AND buried early in the file is far weaker than one with any single issue. The effect is multiplicative, not additive.

## Antipatterns

- Writing a short, hedged instruction early in the file ("you might want to consider formatting"). This stacks three weaknesses: brevity, hedged modality, and early position. Each weakness multiplies the others.
- Using abstract language in a hedged instruction ("consider using appropriate tools for code quality"). Abstract + hedged is far weaker than either alone.
- Burying a terse constraint at the top of the file without naming specific constructs. Position, length, and specificity weaknesses compound into near-zero compliance.

## Pass / Fail

### Pass

~~~~markdown
Use `ruff` for all formatting in `src/` and `tests/`.
Run `uv run pytest tests/ -v` before committing changes.
NEVER use `black` or manual formatting.
~~~~

### Fail

~~~~markdown
You might want to think about code quality.
Consider using appropriate tools.
Perhaps run tests sometimes.
~~~~

## Fix

Never stack weaknesses. A short instruction MUST name specific constructs and go near the end of the file. An abstract instruction MUST use direct language, include multiple relevant terms, and be positioned last. Fixing ANY ONE weakness dramatically improves the instruction — but leaving multiple weaknesses is catastrophic. Elaborating with distinct relevant terms (not repetition) is the easiest fix.

## Limitations

Detects individual weakness factors (specificity, modality, position, length) and flags when multiple co-occur. The compound effect is estimated, not directly measured.
