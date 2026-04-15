---
id: CORE:C:0027
slug: mcp-configuration-documented
title: "Mcp Configuration Documented"
category: coherence
type: mechanical
severity: medium
backed_by: []
match: {type: main}
---
# Mcp Configuration Documented

The main instruction file must contain a heading referencing MCP, Server, or Tools. If the project uses MCP tools, documenting them in the main file ensures the agent discovers available servers at session start.

## Antipatterns

- Describing MCP servers in a scoped rule file but not in the main instruction file -- the check targets main-type files only, so documentation in `.claude/rules/mcp.md` does not satisfy it.
- Using a heading like "## Integrations" to document MCP server setup -- the check requires the heading to contain "MCP", "Server", or "Tools".
- Mentioning server names in a bullet list under a generic heading like "## Setup" -- the heading-match check scans headings, not list content.

## Pass / Fail

### Pass

~~~~markdown
## MCP Server Configuration

- filesystem: scoped to project root, read/write
- github: PR and issue operations on current repo
~~~~

### Fail

~~~~markdown
## Project Setup

Install dependencies with `npm install`.
The agent can use filesystem and github tools.
~~~~

## Limitations

Checks for headings matching topic keywords. Does not evaluate the quality or completeness of the content under those headings.
