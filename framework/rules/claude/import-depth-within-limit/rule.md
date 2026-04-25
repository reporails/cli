---
id: CLAUDE:S:0010
slug: import-depth-within-limit
title: Import Depth Within Limit
category: structure
type: mechanical
severity: medium
match: {type: main}
source: https://code.claude.com/docs/en/memory#import-additional-files
---

# Import Depth Within Limit

Import chains should not exceed 3 levels deep. Deep import hierarchies increase context loading time and create fragile dependency chains — a change to a deeply nested file can silently break the import resolution of files several levels up.

## Antipatterns

- **Transitive chaining.** `CLAUDE.md` imports `docs/setup.md`, which imports `docs/details/config.md`, which imports `docs/details/advanced/tuning.md`, which imports a 5th file. The chain exceeds 3 levels and any broken link silently drops content.
- **Circular imports.** File A imports B, B imports C, C imports A. The resolver must detect and break the cycle, but the author likely didn't intend it.
- **Import as organization substitute.** Using `@import` chains to simulate a file hierarchy instead of structuring content into focused files that the agent loads directly.

## Pass / Fail

### Pass

~~~~markdown
<!-- CLAUDE.md (depth 0) -->
@import docs/testing.md
@import docs/formatting.md

<!-- docs/testing.md (depth 1) -->
@import docs/fixtures.md

<!-- docs/fixtures.md (depth 2) — within limit -->
# Test Fixtures
Use `conftest.py` for shared setup.
~~~~

### Fail

~~~~markdown
<!-- CLAUDE.md (depth 0) -->
@import docs/overview.md

<!-- docs/overview.md (depth 1) -->
@import docs/details.md

<!-- docs/details.md (depth 2) -->
@import docs/internals.md

<!-- docs/internals.md (depth 3) -->
@import docs/deep/config.md  ← depth 4, exceeds limit
~~~~

## Limitations

Counts import depth from the root instruction file. Does not evaluate whether deep imports are justified by project complexity. Only follows `@import` syntax — other inclusion mechanisms are not detected.
