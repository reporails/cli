---
id: CURSOR:S:0006
slug: import-depth-within-limit
title: Import Depth Within Limit
category: structure
type: mechanical
severity: high
match: {type: main}
supersedes: CORE:S:0033
source: https://cursor.com/docs/rules
---

# Import Depth Within Limit

Cursor's `@filename` syntax in `AGENTS.md` and `.cursor/rules/*.mdc` is **single-level only** — referenced files are pulled into context, but `@<path>` syntax inside those referenced files is not transitively followed. This stub supersedes the more permissive CORE ceiling with Cursor's actual single-level model so a chained-import pattern (which Cursor does not honor) is flagged early.

## Antipatterns

- **Assuming transitive resolution.** Writing `@docs/setup.md` in `AGENTS.md` and embedding `@docs/details.md` inside `docs/setup.md` expecting the second file to load. Cursor only reads the first reference; the inner `@<path>` is rendered as text.
- **Using `@<path>` to simulate include chains.** Treating `@filename` as Claude Code's `@import` and building multi-level hierarchies. The agent loads exactly one level of references.

## Pass / Fail

### Pass

~~~~markdown
<!-- AGENTS.md -->
@docs/style/formatting.md
@docs/testing-conventions.md
~~~~

### Fail

~~~~markdown
<!-- AGENTS.md (depth 0) -->
@docs/overview.md

<!-- docs/overview.md (depth 1) -->
@docs/details.md   ← Cursor will not follow this; depth 2 reached
~~~~

## Limitations

Counts depth from the root instruction file. Cursor's documentation does not formalize whether multi-level `@<path>` chains are silently truncated or fully ignored — this rule treats anything past depth 1 as a smell so authors don't rely on a behavior the docs don't promise. Other inclusion mechanisms (e.g., a `cursor.json` reference list) are not detected.
