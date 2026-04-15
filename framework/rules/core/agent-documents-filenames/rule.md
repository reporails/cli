---
id: CORE:S:0012
slug: agent-documents-filenames
title: "Agent Documents Filenames"
category: structure
type: deterministic
severity: medium
backed_by: []
match: {type: scoped_rule}
---

# Agent Documents Filenames

Agent configuration must document which instruction filenames it checks and in what priority order.

## Antipatterns

- Describing agent behavior generically ("the agent reads configuration files") without naming specific instruction filenames like `CLAUDE.md` or `.cursorrules`. The check looks for recognized filenames, not general descriptions.
- Listing only one agent's filename when the file covers multiple agents. The check passes with any recognized filename, but a single-agent list in a multi-agent scoped rule leaves gaps.
- Using informal references like "the main config" instead of the actual filename. The pattern matches literal filenames and the words "filename" or "file name" -- synonyms like "config" or "settings" do not match.

## Pass / Fail

### Pass

~~~~markdown
# Discovery

Claude Code reads `CLAUDE.md` at session start.
Cursor checks `.cursorrules` in the project root.
Copilot loads `copilot-instructions.md` from `.github/`.
~~~~

### Fail

~~~~markdown
# Discovery

The agent reads its configuration from the project root.
Priority is determined by the loading order.
~~~~

## Limitations

Checks that the file documents recognized instruction filenames. Does not validate whether the documented filenames match actual project files.
