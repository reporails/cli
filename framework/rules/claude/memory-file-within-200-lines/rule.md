---
id: CLAUDE:S:0011
slug: memory-file-within-200-lines
title: Memory File Length Limit
category: structure
type: mechanical
severity: medium
match: {type: memory}
source: https://code.claude.com/docs/en/memory#auto-memory
---

# Memory File Length Limit

MEMORY.md should stay under 200 lines. Lines beyond 200 are truncated by Claude Code — content past the cutoff is silently dropped from the agent's context. Keep the index concise — store detail in linked memory files, not inline.

## Antipatterns

- **Inline memory content.** Writing full memory entries directly in MEMORY.md instead of linking to separate `.md` files. Each entry should be a one-line pointer, not a paragraph.
- **Stale accumulation.** Never pruning old or outdated memory entries. Over time, MEMORY.md grows past 200 lines and the newest entries (at the bottom) are the ones truncated.
- **Verbose link descriptions.** Writing multi-line descriptions for each memory link instead of keeping each entry under ~150 characters as a scannable index.

## Pass / Fail

### Pass

~~~~markdown
# Memory

- [User role](user_role.md) — Senior engineer, Go + React
- [Testing preference](feedback_testing.md) — Integration tests, no mocks
- [Deploy process](project_deploy.md) — CI/CD via GitHub Actions
~~~~

### Fail

~~~~markdown
# Memory

## User Profile
The user is a senior software engineer with 10 years of experience
in Go and 2 years in React. They prefer integration tests over unit
tests because of a past incident where mocked tests passed but the
production migration failed. Their deploy process uses GitHub Actions
with a staging environment...
[... 250 lines of inline content]
~~~~

## Limitations

The 200-line limit is based on Claude Code's truncation behavior. Future versions may change this threshold. Counts total lines including blank lines and headings.
