---
id: CLAUDE:S:0011
slug: memory-file-within-200-lines
title: "Memory File Length Limit"
category: structure
type: mechanical
severity: medium
match: {type: memory}
---

# Memory File Length Limit

MEMORY.md should stay under 200 lines. Lines beyond 200 are truncated by Claude Code. Keep the index concise — store detail in linked memory files, not inline.

## Limitations

The 200-line limit is based on Claude Code's truncation behavior. Future versions may change this threshold.
