# Reporails CLI

Lint and score CLAUDE.md files — MCP-first AI context governance.

## Installation

### MCP Server (recommended)

```bash
claude mcp add --scope user --transport stdio reporails -- uvx --from reporails-cli ails-mcp
```

Then in Claude Code: "Check my CLAUDE.md"

### CLI

```bash
pip install reporails-cli
```

## Usage

```bash
ails check .              # Validate instruction files
ails check . -f json      # Output as JSON
ails map . --save         # Generate backbone.yml
ails explain S1           # Show rule details
```

## How It Works

1. Loads rules from `~/.reporails/checks/` (auto-downloaded on first run)
2. Runs OpenGrep (auto-downloaded) with rule patterns
3. Calculates score (0-10) and capability level (L1-L6)
4. For semantic rules, returns JudgmentRequests for host LLM

## Rule Categories

| Category | Rules | Focus |
|----------|-------|-------|
| Structure (S) | S1-S7 | File size, organization |
| Content (C) | C1-C12 | Clarity, completeness |
| Efficiency (E) | E1-E8 | Token usage, context |
| Maintenance (M) | M1-M7 | Versioning, review |
| Governance (G) | G1-G8 | Policies, ownership |

## Development

```bash
uv sync                                  # Install dependencies
uv run ails check . --checks-dir checks  # Run against local rules
uv run poe qa                            # Full test suite
```

### MCP Setup

To use the reporails MCP server during development:

1. Copy `.claude/mcp.json.example` to `.claude/mcp.json`
2. Replace `<PROJECT_ROOT>` with the absolute path to this repo

## License

Apache 2.0
