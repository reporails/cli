---
id: CORE:S:0033
slug: import-depth-within-limit
title: Import Depth Within Limit
category: structure
type: mechanical
severity: high
match: {type: main}
source: https://code.claude.com/docs/en/memory#import-additional-files
---

# Import Depth Within Limit

Import chains in root instruction files should be bounded. Deep import hierarchies increase context loading time and create fragile dependency chains; a change to a deeply nested file can silently break import resolution of files several levels up. The CORE check enforces a permissive absolute ceiling (10 hops) — agents whose `@<path>` syntax has a documented behavior should declare a per-agent supersede stub with the actual threshold. Of the agents currently in the registry: Claude defines a 5-hop hard limit (see `CLAUDE:S:0010`); Cursor's `@filename` is single-level only (see `CURSOR:S:0006`); Antigravity supports chained `@file.md` imports without a documented max and inherits the CORE ceiling; Codex and Copilot declare `CORE:S:0033` in their `config.yml` `excludes:` because their instruction files do not honor any `@<path>` inclusion syntax.

## Antipatterns

- **Transitive chaining.** `CLAUDE.md` imports `docs/setup.md`, which imports `docs/details/config.md`, which imports `docs/details/advanced/tuning.md`, which imports a deeper file, hitting the 5-hop limit. Any broken link past depth 5 is silently dropped.
- **Circular imports.** File A imports B, B imports C, C imports A. The resolver must detect and break the cycle, but the author likely didn't intend it.
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

<!-- docs/style/fixtures.md (depth 3) — within limit -->
# Test Fixtures
Use `conftest.py` for shared setup.
~~~~

### Fail

~~~~markdown
<!-- CLAUDE.md (depth 0) -->
@import docs/overview.md
<!-- docs/overview.md → docs/details.md → docs/internals.md →
     docs/deep/a.md → docs/deep/b.md → docs/deep/c.md  ← depth 6, exceeds 5 -->
~~~~

## Limitations

Counts import depth from the root instruction file. Does not evaluate whether deep imports are justified by project complexity. Only follows `@`-prefixed inclusion syntax — agent-specific alternatives that don't use `@<path>` are not detected. The CORE-level threshold of 10 is a deliberately permissive sanity ceiling; per-agent supersede stubs (e.g., `CLAUDE:S:0010` at 5 hops) carry the agent's documented hard limit. Agents that don't support chained imports declare `excludes: [CORE:S:0033]` in their `config.yml` so the rule never runs against their files.
