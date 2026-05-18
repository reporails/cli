---
id: CLAUDE:S:0010
slug: import-depth-within-limit
title: Import Depth Within Limit
category: structure
type: mechanical
severity: high
match: {type: main}
supersedes: CORE:S:0033
source: https://code.claude.com/docs/en/memory#import-additional-files
---

# Import Depth Within Limit

Claude Code's `CLAUDE.md` `@import` chains have a documented hard limit of **5 hops**. Imports beyond depth 5 are not resolved — content past the cutoff is silently dropped. This stub supersedes the more permissive CORE ceiling with Claude's actual documented threshold so the agent-specific cap is enforced when the project is scanned with `--agent claude` or when Claude is auto-detected.

## Antipatterns

- **Transitive chaining past 5.** `CLAUDE.md` imports `docs/setup.md`, which imports `docs/details/config.md`, and the chain continues past depth 5. Claude Code stops following imports at the 5-hop boundary and the deeper content is not in context.
- **Circular imports.** File A imports B, B imports C, C imports A. Claude Code's resolver detects and breaks the cycle, but the author likely didn't intend it.
- **Import as organization substitute.** Using `@import` chains to simulate a file hierarchy instead of structuring content into focused files that the agent loads directly.

## Pass / Fail

### Pass

~~~~markdown
<!-- CLAUDE.md (depth 0) -->
@import docs/testing.md

<!-- docs/testing.md (depth 1) -->
@import docs/style/formatting.md

<!-- docs/style/formatting.md (depth 2) -->
@import docs/style/fixtures.md

<!-- docs/style/fixtures.md (depth 3) — well within Claude's 5-hop limit -->
# Test Fixtures
Use `conftest.py` for shared setup.
~~~~

### Fail

~~~~markdown
<!-- CLAUDE.md (depth 0) -->
@import docs/overview.md
<!-- docs/overview.md → docs/details.md → docs/internals.md →
     docs/deep/a.md → docs/deep/b.md → docs/deep/c.md  ← depth 6, exceeds Claude's 5 -->
~~~~

## Limitations

Counts depth from the root `CLAUDE.md`. Does not evaluate whether the chain is justified by project complexity. Only follows `@<path>` syntax — other inclusion mechanisms are not detected. The 5-hop ceiling is Claude Code's documented hard truncation; future Claude Code versions may revise it.
