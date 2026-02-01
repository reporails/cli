# @reporails/cli

Score your CLAUDE.md files. See what's missing. Improve your AI coding setup.

## Install MCP Server (Claude Code)

```bash
npx @reporails/cli install
```

This registers the reporails MCP server with Claude Code. Then ask Claude:

```
> What ails claude?
```

## CLI Usage

```bash
# Score your setup
npx @reporails/cli check .

# JSON output (for CI)
npx @reporails/cli check . -f json

# Explain a rule
npx @reporails/cli explain S1

# Show project structure
npx @reporails/cli map .
```

## Commands

| Command | Description |
|---------|-------------|
| `install [--scope user\|project]` | Register MCP server with Claude Code |
| `uninstall [--scope user\|project]` | Remove MCP server from Claude Code |
| `check [PATH]` | Validate instruction files |
| `map [PATH]` | Discover project structure |
| `explain RULE_ID` | Show rule details |
| `version` | Show version info |

## Prerequisites

- **Node.js >= 18**
- **uv** — auto-installed if missing ([manual install](https://docs.astral.sh/uv/))
- **Claude Code** — required for `install`/`uninstall` commands ([install](https://docs.anthropic.com/en/docs/claude-code))

## How It Works

This is a thin Node.js wrapper around the [reporails-cli](https://pypi.org/project/reporails-cli/) Python package. Commands are proxied via `uvx` — no Python installation required.

## License

Apache-2.0
