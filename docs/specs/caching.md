# Caching & Discovery

Discovery system and caching strategy for reporails.

## Generated Files

```
project/
├── .reporails/
│   ├── backbone.yml      # Component hierarchy (committed)
│   └── .cache/
│       ├── file-map.json       # Cached instruction file locations (gitignored)
│       └── judgment-cache.json # Semantic judgment cache (gitignored)
```

## backbone.yml Structure

```yaml
version: 1
generated_at: "2024-01-23T10:30:00Z"
generator: "ails discover"

agents:
  claude:
    name: "Claude (Anthropic)"
    instruction_files: [...]
    rule_files: [...]

components:
  root:
    instruction_files: ["CLAUDE.md"]
    content_hash: "sha256:abc123..."
    imports: [".shared/sys.yml"]

  app.agents:
    instruction_files: ["app/agents/CLAUDE.md"]
    content_hash: "sha256:def456..."
    imports: ["../../.shared/rules/agents.md"]
    parent: "root"

shared:
  - ".shared/sys.yml"
  - ".shared/rules/*.md"
```

## Caching Strategy

Hybrid caching: project-local for operations, global for analytics.

### Project-Local Cache (`.reporails/`)

| File | Purpose | Invalidation |
|------|---------|--------------|
| `backbone.yml` | Component hierarchy (committed) | `ails map --save` |
| `.cache/file-map.json` | Skip filesystem scan (gitignored) | `--refresh` flag or file deletion |
| `.cache/judgment-cache.json` | Skip semantic re-evaluation (gitignored) | Content hash mismatch |

### Global Cache (`~/.reporails/`)

| Directory | Purpose | Notes |
|-----------|---------|-------|
| `bin/` | OpenGrep binary | Auto-downloaded on first `check` |
| `checks/` | Bundled rule definitions | Updated with CLI |
| `analytics/projects/{id}.json` | Per-project scan history | Quiet collection, last 100 scans |

## Project Identification

Projects are identified by a 12-character hash:
1. **Git remote URL** (preferred) - consistent across clones
2. **Absolute path** (fallback) - when no git remote

## Related Docs

- [Architecture Overview](arch.md)
- [Module Specifications](modules.md) — `cache.py`, `discover.py` details
