# Architecture Overview

> Version 0.2.0 | AI Instruction Validator

## Overview

Reporails validates AI coding agent instruction files against community-maintained rules.

| Purpose | Name |
|---------|------|
| Brand/Package | `reporails` |
| CLI Command | `ails` |
| MCP Server | `ails-mcp` |

## Core Principles

- **MCP-First**: Primary interface is MCP for Claude Code integration
- **OpenGrep-Powered**: Uses OpenGrep for deterministic pattern matching
- **Rules as Data**: Rules defined in markdown frontmatter + OpenGrep YAML
- **Framework Separation**: CLI orchestrates, framework defines rules
- **No Detection Logic in Python**: Python orchestrates, OpenGrep detects

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
│   Init    │ Discovery │  Engine   │  Registry │     Scorer      │
└───────────┴───────────┴───────────┴───────────┴─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      External Layer                             │
├─────────────────────────────────┬───────────────────────────────┤
│       OpenGrep Binary           │       Framework (Rules)       │
│    (~/.reporails/bin/)          │    (~/.reporails/rules/)      │
└─────────────────────────────────┴───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Output Layer                              │
├───────────────────────────────────┬─────────────────────────────┤
│         JSON Format               │        Text Format          │
│    (canonical, for MCP)           │      (CLI display)          │
└───────────────────────────────────┴─────────────────────────────┘
```

## Directory Structure

### CLI Repository

```
reporails-cli/
├── src/reporails_cli/
│   ├── core/
│   │   ├── init.py           # Re-exports + run_init()
│   │   ├── download.py       # Download OpenGrep, rules, recommended
│   │   ├── updater.py        # Version fetching + update orchestration
│   │   ├── bootstrap.py      # Path helpers
│   │   ├── levels.py         # Level config, rule mapping
│   │   ├── discover.py       # Project discovery
│   │   ├── engine.py         # Validation orchestration
│   │   ├── engine_helpers.py  # Validation sub-functions
│   │   ├── registry.py       # Rule loading + resolution
│   │   ├── rule_builder.py   # Rule construction + tier derivation
│   │   ├── scorer.py         # Score calculation
│   │   ├── models.py         # Core data models (enums, Rule, Violation)
│   │   ├── results.py        # Result models (features, configs, ValidationResult)
│   │   ├── cache.py          # Judgment caching
│   │   ├── analytics.py      # Scan analytics + project identification
│   │   ├── update_check.py   # Update staleness detection + pre-run prompt
│   │   ├── self_update.py    # CLI self-upgrade
│   │   ├── mechanical/       # Mechanical rule checks (package)
│   │   │   ├── checks.py     # Simple checks + registry
│   │   │   └── checks_advanced.py  # Complex checks
│   │   ├── opengrep/         # OpenGrep execution (package)
│   │   │   ├── runner.py     # Binary execution
│   │   │   ├── templates.py  # {{placeholder}} resolution
│   │   │   └── semgrepignore.py
│   │   └── sarif.py          # SARIF parsing
│   ├── bundled/              # CLI-owned config (not downloaded)
│   │   └── capability-patterns.yml
│   ├── templates/            # CLI output templates
│   ├── interfaces/
│   │   ├── mcp/server.py     # MCP server
│   │   └── cli/
│   │       ├── main.py       # check + explain commands
│   │       ├── commands.py   # map, sync, update, judge, version
│   │       └── helpers.py    # Shared CLI utilities
│   └── formatters/
│       ├── json.py           # Canonical format
│       ├── text/             # Terminal display (package)
│       │   ├── full.py       # Full output
│       │   ├── compact.py    # Non-TTY output
│       │   ├── box.py        # Assessment box
│       │   ├── violations.py # Violation rendering
│       │   └── ...
│       └── mcp.py            # MCP wrapper
├── docs/specs/               # Architecture docs
└── tests/
    ├── unit/                 # Fast, isolated unit tests
    └── integration/          # Tests requiring OpenGrep
```

### Bundled vs Downloaded

| Content | Location | Source | Purpose |
|---------|----------|--------|---------|
| **Bundled** | `src/bundled/` | CLI package | Orchestration logic |
| **Downloaded** | `~/.reporails/rules/` | Framework release | Rule definitions |
| **Downloaded** | `~/.reporails/packages/recommended/` | Recommended release | Additional rules |

**Bundled (CLI-owned):**
- `capability-patterns.yml` — OpenGrep patterns for feature detection

**Downloaded (Framework-owned):**
- `core/` — Rule definitions (.md + .yml)
- `agents/` — Agent-specific rules
- `schemas/` — Rule schema definitions
- `registry/` — Levels, capabilities, coordinate map
- `docs/` — Reference documentation

This separation ensures:
- CLI controls how levels work (orchestration)
- Framework controls what rules exist (data)
- CLI can upgrade independently of framework

### Runtime Structure

```
~/.reporails/
├── bin/
│   └── opengrep                  # Downloaded binary
├── rules/                        # Downloaded framework
│   ├── core/                     # Core rules
│   │   ├── structure/
│   │   ├── content/
│   │   ├── efficiency/
│   │   ├── governance/
│   │   └── maintenance/
│   ├── agents/                   # Agent-specific rules
│   │   └── claude/
│   │       ├── config.yml
│   │       └── rules/
│   ├── schemas/                  # Rule schemas
│   └── docs/                     # Reference docs
│       ├── capability-levels.md
│       ├── methodology-thresholds.md
│       └── sources.yml
├── packages/                     # Downloaded rule packages
│   └── recommended/              # Recommended rules (AILS_ namespace)
│       └── .version              # Installed recommended version
├── cache/
│   └── update-check.json         # Update staleness cache (24h TTL)
├── config.yml                    # Global user config (optional)
└── version                       # Installed framework version
```

### Project Structure (User's Repo)

```
project/
├── CLAUDE.md                     # Root instruction file
├── .claude/
│   └── rules/                    # Path-scoped rules
├── .reporails/                   # Project-level config
│   ├── config.yml                # Overrides, disabled rules
│   ├── rules/                    # Custom rules (user's own)
│   │   ├── my-rule.md
│   │   └── my-rule.yml
│   └── overrides/                # Override framework rules
│       └── CORE-S-0001.yml       # Different threshold
└── .reporails/.cache/            # Gitignored
    ├── file-map.json
    └── judgment-cache.json
```

## First Run Flow

```
User runs: ails check
           │
           ▼
┌─────────────────────────────┐
│  Check ~/.reporails/        │
│  - bin/opengrep exists?     │
│  - rules/ exists?           │
└─────────────────────────────┘
           │
           ▼ (missing)
┌─────────────────────────────┐
│  Download OpenGrep          │
│  - Detect OS/arch           │
│  - Download binary          │
│  - Verify checksum          │
│  - Extract to bin/          │
└─────────────────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Download Framework         │
│  - Fetch latest release     │
│  - Download tarball         │
│  - Verify checksum          │
│  - Extract to rules/        │
│  - Write version file       │
└─────────────────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Run Validation             │
└─────────────────────────────┘
```

## Rule Resolution

Rules are resolved in priority order (later overrides earlier):

```
1. ~/.reporails/rules/core/              # Framework core rules
2. ~/.reporails/rules/agents/{agent}/    # Framework agent rules
3. .reporails/overrides/                 # Project overrides
4. .reporails/rules/                     # Project custom rules
```

**Resolution logic:**

- Rules matched by ID (e.g., `CORE:S:0001`)
- Override replaces entire rule (not merge)
- Custom rules add to rule set
- Disabled rules removed from set

**Example:**

```yaml
# .reporails/config.yml
disabled_rules:
  - CORE:S:0001     # Disable size limits entirely
  - CORE:C:0007     # Disable emphasis discipline

overrides:
  CORE:S:0003:
    severity: low   # Demote code block check
```

## Rule Types

Three rule types (defined in framework `schemas/rule.schema.yml`):

| Type | Detection | LLM | Output |
|------|-----------|-----|--------|
| **Deterministic** | OpenGrep pattern → direct result | No | `Violation` |
| **Mechanical** | Python structural check → direct result | No | `Violation` |
| **Semantic** | Content extraction → LLM evaluation | Yes | `JudgmentRequest` |

### Deterministic Flow

```
OpenGrep runs .yml pattern
        │
        ▼
    Match found?
        │
    ┌───┴───┐
    No      Yes
    │       │
    ▼       ▼
  Pass    Violation
```

### Mechanical Flow

```
Python function dispatched
        │
        ▼
    CheckResult
        │
    ┌───┴───┐
  Pass     Fail
            │
            ▼
        Violation
```

### Semantic Flow

```
Engine extracts content
        │
        ▼
  Build JudgmentRequest
  (question, criteria)
        │
        ▼
  Return to host LLM
        │
        ▼
  LLM evaluates
        │
        ▼
  JudgmentResponse
        │
    ┌───┴───┐
  Pass     Fail
            │
            ▼
        Violation
```

## Agent Support

**Currently supported (v0.0.1):**
- Claude: `CLAUDE.md`, `.claude/rules/*.md`

**Discovery-ready (detection only, no validation rules yet):**

| Agent | Instruction Files | Status |
|-------|-------------------|--------|
| Cursor | `.cursorrules`, `.cursor/rules/*.md` | Detected |
| Windsurf | `.windsurfrules` | Detected |
| GitHub Copilot | `.github/copilot-instructions.md` | Detected |
| Aider | `.aider.conf.yml`, `CONVENTIONS.md` | Detected |
| Generic | `AGENTS.md`, `.ai/**/*.md` | Detected |

## Commands

```bash
# Validation
ails check [PATH]              # Validate instruction files
ails check [PATH] --refresh    # Force re-scan, ignore cache
ails check [PATH] -f json      # Output as JSON (for MCP/scripts)
ails check [PATH] -q           # Suppress semantic rules message
ails check [PATH] --no-update-check  # Skip pre-run update prompt
ails check [PATH] --exclude-dir vendor  # Exclude directory (repeatable)
# Note: recommended rules are included by default (opt out in .reporails/config.yml)

# Management
ails update                    # Update rules framework + recommended
ails update --check            # Check for updates without installing
ails update --recommended      # Update recommended rules only
ails update --force            # Force reinstall even if current
ails update --version 0.1.0    # Update framework to specific version
ails update --cli              # Upgrade CLI package itself

# Information
ails explain RULE_ID           # Show rule details
ails version                   # Show CLI, framework, and recommended versions
```

## Configuration

### Global Config (`~/.reporails/config.yml`)

```yaml
# Framework source (default: GitHub releases)
framework_path: null           # Local path override (dev only)

# Update behavior
auto_update_check: true        # Check for updates weekly
```

### Project Config (`.reporails/config.yml`)

```yaml
# Pin framework version
framework_version: "0.0.1"

# Disable rules
disabled_rules:
  - CORE:S:0001
  - CORE:C:0007

# Override severity
overrides:
  CORE:S:0003:
    severity: low
  CORE:E:0006:
    severity: low

# Opt out of recommended rules (included by default)
recommended: false
```

## OpenGrep Integration

Pattern matching powered by [OpenGrep](https://github.com/opengrep/opengrep).

### Severity Mapping

| OpenGrep Level | Engine Behavior |
|----------------|-----------------|
| `ERROR` | Creates `Violation` |
| `WARNING` | Creates `Violation` |
| `INFO` | Skipped |

### Platform Support

| OS | Architecture | Binary |
|----|--------------|--------|
| Linux | x86_64, aarch64 | opengrep-linux-* |
| macOS | x86_64, arm64 | opengrep-darwin-* |
| Windows | x86_64 | opengrep-windows-*.exe |

## Quality Gates

- `poe qa_fast` — format, lint, pylint structural, type check, unit tests (pre-commit)
- `poe qa` — full QA including integration tests

## Related Docs

- [Caching & Discovery](caching.md)
- [Scoring](scoring.md)
- [Architecture Principles](principles.md)
- [Module Specifications](modules.md)
- [Data Models](models.md)
