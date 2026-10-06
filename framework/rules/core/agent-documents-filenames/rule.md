---
id: CORE:S:0012
slug: agent-documents-filenames
title: Agent Documents Filenames
category: structure
type: deterministic
severity: medium
backed_by: []
match: {type: main}
source: https://agents.md/
---

# Agent Documents Filenames

The main instruction file must document which instruction filenames its agents read and in what priority order.

## Antipatterns

- Describing agent behavior generically ("the agent reads configuration files") without naming the instruction files, such as `AGENTS.md`. The check looks for recognized filenames, not general descriptions.
- Naming an agent's own instruction file, such as `CLAUDE.md` or `copilot-instructions.md`, in a file several agents share, such as `AGENTS.md`. The shared file names the files every agent reads and which one takes precedence; each agent's own file names what that agent reads. Cross Agent Compatibility (`CORE:C:0026`) flags an agent's own filename in a shared file.
- Using informal references like "the main config" instead of the actual filename. The pattern matches literal filenames and the words "filename" or "file name" -- synonyms like "config" or "settings" do not match.

## Pass / Fail

### Pass

~~~~markdown
# Instruction files

`AGENTS.md` at the project root holds the instructions every agent shares.
A closer `AGENTS.md` in a subdirectory takes precedence for the files under it.
~~~~

### Fail

~~~~markdown
# Discovery

The agent reads its configuration from the project root.
Priority is determined by the loading order.
~~~~

## Limitations

Checks the project's main instruction file. Checks that it documents recognized instruction filenames. Does not validate whether the documented filenames match actual project files.
