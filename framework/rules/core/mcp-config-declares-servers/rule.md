---
id: CORE:G:0008
slug: mcp-config-declares-servers
title: Mcp Config Declares Servers
category: governance
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents]
match: {type: config}
---
# Mcp Config Declares Servers

Config files must contain a heading referencing MCP or mcpServers. Without declared server entries, the agent has no record of which MCP tools are available or how they are scoped.

## Antipatterns

- A config file that references MCP tools in prose but has no heading containing "MCP" or "mcpServers" -- the heading-match check looks for those terms in section headers, not body text.
- Adding a heading like "## External Tools" that describes MCP servers without using the term "MCP" in the heading -- the check requires the heading itself to match.
- Declaring servers only in a separate JSON/YAML config without any heading reference in the instruction config file -- the check targets config-type instruction files, not raw tool configs.

## Pass / Fail

### Pass

~~~~markdown
## MCP Servers

- filesystem: read/write access to project directory
- github: issue and PR operations, scoped to current repo
~~~~

### Fail

~~~~markdown
## External Integrations

We use several MCP tools for file access and GitHub operations.
See the settings file for details.
~~~~

## Limitations

Checks for a heading containing "MCP" or "mcpServers". Does not verify the config declares valid server entries with tool allowlists.
