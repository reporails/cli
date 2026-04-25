---
id: CORE:S:0023
slug: agent-memory-directory
title: Agent Memory Directory
category: structure
type: mechanical
severity: medium
backed_by: []
match: {type: memory}
source: https://code.claude.com/docs/en/memory#auto-memory
---

# Agent Memory Directory

Agent memory must be stored in a dedicated directory, separate from instruction content.

## Antipatterns

- Storing memory files alongside instruction rules in `.claude/rules/` instead of a dedicated memory directory. Memory and rules serve different purposes and the check expects a separate memory path.
- Creating a memory file at the project root without a containing directory. The check verifies that the memory directory itself exists, not just individual memory files.
- Naming the directory something non-standard that the agent does not recognize. The check looks for the memory directory at the path mapped for the memory file type.

## Pass / Fail

### Pass

~~~~markdown
project/
  .claude/
    memory/
      MEMORY.md
~~~~

### Fail

~~~~markdown
project/
  .claude/
    rules/
      MEMORY.md
~~~~

## Limitations

Checks that the memory directory exists. Does not verify it is writable, contains expected subdirectories, or that memory files within it are valid.
