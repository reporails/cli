---
id: CORE:C:0029
slug: no-ephemeral-content
title: No Ephemeral Content
category: coherence
type: deterministic
severity: high
backed_by: [claude-code-issue-13579, spec-writing-for-agents]
match: {format: freeform}
---

# No Ephemeral Content

Instruction files must not contain ephemeral markers like TODO, FIXME, or WIP. These indicate incomplete content that shouldn't be committed.

## Antipatterns

- Leaving a `TODO: add testing instructions` comment in a committed instruction file -- the check flags `TODO:` as an ephemeral marker.
- Using `WIP:` as a section prefix to mark draft content -- the pattern matches `WIP:` regardless of position.
- Adding a `FIXME: update after migration` note intending to clean it up later -- ephemeral markers in committed instruction files indicate the content is not ready for use.
- Marking temporary workarounds with `HACK:` or `TEMP:` -- both are flagged by the pattern.

## Pass / Fail

### Pass

~~~~markdown
## Testing

Run `pytest tests/` before every commit.
Keep integration tests in `tests/integration/`.
~~~~

### Fail

~~~~markdown
## Testing

TODO: add testing instructions
FIXME: update test command after migration
WIP: this section is incomplete
~~~~

## Limitations

Detects common ephemeral markers (TODO, FIXME, HACK, TEMP, WIP, PLACEHOLDER). May miss custom or unlabeled temporary content.
