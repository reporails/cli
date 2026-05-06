---
id: CORE:C:0055
slug: description-coherence
title: "Description Coherence"
category: coherence
type: mechanical
execution: server
severity: medium
match: {loading: on_invocation}
---

# Description Coherence

Files that the agent loads on demand — skills, subagents, slash commands — are dispatched by their frontmatter `description:` field. The agent reads the description first, decides whether the file applies, and only then loads the body. When the description names a narrower concept than the body covers, or when the description and the body are about different topics altogether, the agent never invokes the file for the cases it actually contains.

## Antipatterns

- A description that names one narrow concept while the body covers a wider workflow. "Format JSON output" as the description for a body that documents JSON, YAML, and CSV.
- A description that's a generic blurb ("Helper utilities") with no overlap to the specific topics in the body. The agent has nothing to dispatch on.
- A description copied from another file at scaffold time and never updated as the body evolved away from it.

## Pass / Fail

### Pass

~~~~markdown
---
name: format-output
description: Format the agent's response as JSON, YAML, or CSV with examples for each. Use when the user asks for structured output or specifies a serialization format.
---

# Format Output

When the user asks for JSON, render keys in lowercase snake_case…
When the user asks for YAML, prefer flow style for short objects…
When the user asks for CSV, escape commas with double quotes…
~~~~

### Fail

~~~~markdown
---
name: format-output
description: Format the agent's response as JSON.
---

# Format Output

When the user asks for JSON, render keys in lowercase snake_case…
When the user asks for YAML, prefer flow style for short objects…
When the user asks for CSV, escape commas with double quotes…
~~~~

## Fix

Rewrite the description so it names the same concepts the body covers. If the body covers three formats, the description should mention all three (or use a covering term like "structured output formats"). The description's job is dispatch: the agent uses it to decide whether the file applies, before paying the cost of loading the body.

## Limitations

Compares description meaning to body meaning at the topic level. Cannot detect when both the description and the body are coherent but neither matches what the user actually wants. Does not fire on path-scoped rule files (loaded by glob match, not by description).
