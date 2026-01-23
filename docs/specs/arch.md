# Architecture Overview

> Version 0.0.1 | AI Instruction Linter

## Overview

Reporails lints AI coding agent instruction files against 42 community-maintained rules.

**repoRAILS** = **Repo** **R**ecursive **AI** **L**inting**S**

| Purpose | Name |
|---------|------|
| Brand/Package | `reporails` |
| CLI Command | `ails` |
| MCP Server | `ails-mcp` |

### Core Principles

- **MCP-First**: Primary interface is MCP for Claude Code integration
- **OpenGrep-Powered**: Uses OpenGrep for pattern matching (lazy-downloaded)
- **Rules as Data**: Rules defined in markdown frontmatter + OpenGrep YAML
- **Backbone-Driven**: Discovery generates backbone.yml for dependency tracking
- **No Detection Logic in Python**: Python orchestrates, OpenGrep detects

### Agent Support

**Currently supported (v0.0.1):**
- Claude: `CLAUDE.md`, `.claude/rules/*.md`

**Discovery-ready (detection only, no linting rules yet):**

| Agent | Instruction Files | Status |
|-------|-------------------|--------|
| Cursor | `.cursorrules`, `.cursor/rules/*.md` | Detected |
| Windsurf | `.windsurfrules` | Detected |
| GitHub Copilot | `.github/copilot-instructions.md` | Detected |
| Aider | `.aider.conf.yml`, `CONVENTIONS.md` | Detected |
| Generic | `AGENTS.md`, `.ai/**/*.md` | Detected |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Interface Layer                        │
├─────────────────────────────────┬───────────────────────────────┤
│          MCP Server             │            CLI                │
│   (interfaces/mcp/server.py)    │   (interfaces/cli/main.py)    │
└─────────────────────────────────┴───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Layer                               │
├───────────┬───────────┬───────────┬───────────┬─────────────────┤
│  Agents   │ Discovery │  Engine   │  Registry │     Scorer      │
└───────────┴───────────┴───────────┴───────────┴─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      External Layer                             │
├─────────────────────────────────┬───────────────────────────────┤
│          OpenGrep Binary        │      Semantic Definitions     │
└─────────────────────────────────┴───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Output Layer                              │
├───────────────────────────────┬─────────────────────────────────┤
│         JSON Format           │          Text Format            │
│    (canonical, for MCP)       │        (CLI display)            │
└───────────────────────────────┴─────────────────────────────────┘
```

### Data Flow

1. **First Run**: Auto-downloads OpenGrep + rules to `~/.reporails/`
2. **Mapping**: `ails map` analyzes project → caches backbone internally
3. **Validation**: User invokes `ails check` (MCP or CLI)
4. **File Map**: Engine uses cached file map (`.reporails/.cache/`)
5. **Registry**: Loads rules from `checks/**/*.md` frontmatter
6. **OpenGrep**: Engine shells out with `.yml` rules → SARIF output
7. **Parsing**: Engine parses SARIF → Violation objects (skips INFO-level)
8. **Scoring**: `calculate_score()` computes 0-10 score
9. **Output**: Formatter adapts output (JSON for MCP, text for CLI)

## File Structure

```
reporails-cli/
├── docs/
│   ├── capability-levels.md # L1-L6 capability levels (user-facing)
│   └── specs/
│       ├── arch.md         # This file
│       ├── caching.md      # Discovery and caching
│       ├── scoring.md      # Scoring and time waste
│       ├── principles.md   # Architecture principles
│       ├── modules.md      # Module specifications
│       └── models.md       # Data models
├── checks/                 # Rule definitions
│   ├── structure/          # S1-S7 (.md + .yml)
│   ├── content/            # C1-C12
│   ├── efficiency/         # E1-E8
│   ├── governance/         # G1-G8
│   └── maintenance/        # M1-M7
├── src/reporails_cli/
│   ├── core/
│   │   ├── agents.py       # Agent definitions (agent-agnostic)
│   │   ├── cache.py        # Hybrid caching (project-local + global analytics)
│   │   ├── discover.py     # Discovery engine
│   │   ├── engine.py       # Validation engine
│   │   ├── models.py       # Data models
│   │   ├── registry.py     # Rule loading
│   │   └── scorer.py       # Scoring functions
│   ├── interfaces/         # MCP + CLI adapters
│   ├── formatters/         # Output adapters
│   └── semantic/           # 6 semantic rule definitions
└── tests/
    ├── unit/
    └── integration/
```

## Commands

```bash
# Validation
ails check [PATH]              # Validate instruction files (auto-installs on first run)
ails check [PATH] --refresh    # Force re-scan, ignore cache
ails check [PATH] -f json      # Output as JSON (for MCP/scripts)
ails check [PATH] -c DIR       # Use custom checks directory

# Mapping
ails map [PATH]                # Map project structure
ails map [PATH] --save         # Save backbone.yml to .reporails/
ails map [PATH] -o yaml        # Output as YAML

# Information
ails explain RULE_ID           # Show rule details
```

## Quality Gates

- `poe qa_fast` — lint, type check, unit tests (pre-commit)
- `poe qa` — full QA including integration tests

## Related Docs

- [Caching & Discovery](caching.md) — Discovery system, caching strategy
- [Scoring](scoring.md) — Score calculation, time waste, semantic rules
- [Architecture Principles](principles.md) — DI, pure functions, hexagonal
- [Module Specifications](modules.md) — Functions per module
- [Data Models](models.md) — Dataclass definitions
- [Capability Levels](../capability-levels.md) — L1-L6 level definitions
