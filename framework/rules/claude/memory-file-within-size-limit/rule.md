---
id: CLAUDE:S:0011
slug: memory-file-within-size-limit
title: Memory File Within Size Limit
category: structure
type: mechanical
severity: medium
match: {type: memory}
source: https://code.claude.com/docs/en/memory#auto-memory
---

# Memory File Within Size Limit

`MEMORY.md` should stay under the host agent's memory truncation threshold. Claude Code loads only the first 200 lines or 25KB of `MEMORY.md` (whichever comes first); content past either cutoff is silently dropped from the agent's context. Other agents that adopt a memory surface may set different caps. Keep the index concise — store detail in linked memory files, not inline.

## Antipatterns

- **Inline memory content.** Writing full memory entries directly in `MEMORY.md` instead of linking to separate `.md` files. Each entry should be a one-line pointer, not a paragraph.
- **Stale accumulation.** Never pruning old or outdated memory entries. Over time, `MEMORY.md` grows past the threshold and the newest entries (at the bottom) are the ones truncated.
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

The 200-line limit enforced here is Claude Code's documented `MEMORY.md` truncation threshold; the parallel 25KB byte cap (whichever comes first per Claude's docs) is not enforced because line_count is the simpler signal. The rule lives in the CLAUDE namespace because the file-system mechanic it checks (a dedicated `MEMORY.md` file under `~/.claude/projects/<project>/memory/`) is Claude-specific: Gemini's "memory" is a section appended to user `GEMINI.md` rather than a separate file; Copilot's memory is a system-managed GitHub repo setting with a 28-day TTL, not on disk; Codex has no memory mechanic; Cursor's memory mechanic is undocumented. If future Claude Code versions change the threshold, or another agent adopts a comparable file-system memory surface, the rule can be promoted to CORE with per-agent supersedes. Counts total lines including blank lines and headings.
