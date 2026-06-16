---
id: CODEX:E:0001
slug: agents-md-within-size-limit
title: AGENTS.md Within Size Limit
category: efficiency
type: mechanical
severity: high
backed_by: []
match: {format: freeform}
source: https://developers.openai.com/codex/guides/agents-md
supersedes: CORE:E:0001
---

# AGENTS.md Within Size Limit

Codex caps the combined `AGENTS.md` instruction chain — global `~/.codex/AGENTS.md` plus every `AGENTS.md` from the git root down to the working directory — at 32 KiB (32,768 bytes) by default, the `project_doc_max_bytes` setting. Content past the cap is silently truncated and never reaches the model, with no warning. Keep the eager `AGENTS.md` footprint under 32 KiB, or raise `project_doc_max_bytes` deliberately when you need more.

## Antipatterns

- A large global `~/.codex/AGENTS.md` that crowds repo-specific `AGENTS.md` rules out under the 32 KiB cap. Keep the global file small.
- Embedding documentation, examples, or data tables in `AGENTS.md` instead of splitting into nested-directory `AGENTS.md` files that load only when descended into.
- Assuming everything in a long `AGENTS.md` reaches the model — past 32 KiB it is dropped without notice.

## Pass / Fail

### Pass

~~~~markdown
AGENTS.md chain totaling ~18 KB:
  ~/.codex/AGENTS.md (4 KB) + repo AGENTS.md (14 KB)
Total: ~18 KB -- within the 32 KiB cap; nothing truncated.
~~~~

### Fail

~~~~markdown
AGENTS.md chain totaling ~40 KB:
  ~/.codex/AGENTS.md (28 KB) + repo AGENTS.md (12 KB)
Total: ~40 KB -- Codex silently drops ~8 KB; the repo's own rules may never load.
~~~~

## Limitations

Counts the eager `AGENTS.md` footprint against Codex's default 32 KiB `project_doc_max_bytes`. A project that raises `project_doc_max_bytes` in `config.toml` has a higher real cap; this rule assumes the default.
