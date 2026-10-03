---
id: CORE:G:0008
slug: mcp-config-declares-servers
title: Mcp Config Declares Servers
category: governance
type: mechanical
enforcement_required: true
enforcement_mechanism: managed_settings
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents]
match: {type: mcp}
---
# Mcp Config Declares Servers

The file an agent actually reads for MCP servers must declare at least one. Claude Code reads project-scope servers from `.mcp.json` and user-scope servers from `~/.claude.json` — not from `settings.json`, which has no `mcpServers` key at all. Each agent's own MCP surface is declared under that agent's `mcp` file type; this rule follows that surface, whatever file it names. Without a declared entry, the agent has no record of which MCP tools are available or how they are scoped.

## Antipatterns

- **Looking for servers in the wrong file**: Adding `permissions` or `hooks` to `settings.json` and expecting that to satisfy MCP declaration. Claude Code never reads `mcpServers` from `settings.json` — it reads `.mcp.json` (project scope) or `~/.claude.json` (user scope).
- **MCP tools described only in prose**: Mentioning MCP tools in a comment or a separate doc without a server entry in the MCP config file itself. The check reads that file's own content, not prose about it.
- **Key present but never populated**: Declaring an empty servers object and never filling it in.

## Pass / Fail

### Pass

```json
{
  "mcpServers": {
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] }
  }
}
```

### Fail

```json
{}
```

## Limitations

Checks for a `"mcpServers"` or `"servers"` key (JSON) or a `[mcp_servers.` table (TOML), whichever the active agent's own MCP file format uses. Does not verify the declared servers carry valid scope constraints or a working command.
