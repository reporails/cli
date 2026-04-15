---
id: CORE:C:0040
slug: non-redundant-content
title: "No Cross-File Duplication"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# No Cross-File Duplication

Duplicated instructions across files drift into contradiction as one copy is updated and the other is not. Conflicting instructions severely degrade compliance. However, same-topic reinforcement using different wording is beneficial — distinct instructions that push in the same direction help each other.

## Antipatterns

- Copy-pasting the same constraint verbatim into `CLAUDE.md` and `.claude/rules/testing.md` -- near-identical text across files is flagged as duplication even if both copies are currently correct.
- Duplicating a command reference like "Run `uv run poe qa`" in multiple rule files -- identical phrasing risks drift when one copy is updated but not the other.
- Restating a rule from a scoped file in the main file "for visibility" using the same wording -- use a pointer ("See `.claude/rules/testing.md`") or rephrase to reinforce the same direction with different language.

## Pass / Fail

### Pass

~~~~markdown
<!-- CLAUDE.md -->
Run `uv run poe qa` before committing. See `.claude/rules/testing.md` for details.

<!-- .claude/rules/testing.md -->
Use `pytest` fixtures from `conftest.py` for shared setup. Test boundaries, not happy paths.
~~~~

### Fail

~~~~markdown
<!-- CLAUDE.md -->
Run `uv run poe qa` before committing. Use `pytest` for all tests.

<!-- .claude/rules/testing.md -->
Run `uv run poe qa` before committing. Use `pytest` for all tests.
~~~~

## Fix

Keep each instruction in one canonical location. If two files need the same constraint, designate one as authoritative and reference it from the other. When reinforcing a topic across files, use different wording that pushes the same direction — do not copy-paste identical text.

## Limitations

Detects near-identical text across files using embedding similarity. Same-direction reinforcement with different wording is not flagged — only high-similarity duplicates that risk drift.
