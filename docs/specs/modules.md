# Module Specifications

Implementation blueprint for the CLI. All modules follow the [Architecture Principles](principles.md).

## Module Structure

```
src/reporails_cli/
├── core/
│   ├── bootstrap.py      # Paths, config loading
│   ├── init.py           # Download OpenGrep + framework
│   ├── registry.py       # Load rules, resolution chain
│   ├── levels.py         # Level config, rule-to-level mapping
│   ├── agents.py         # Agent definitions, detection
│   ├── applicability.py  # Feature detection (filesystem)
│   ├── capability.py     # Capability scoring (OpenGrep)
│   ├── discover.py       # Find instruction files
│   ├── engine.py         # Orchestration only
│   ├── opengrep.py       # Run binary, return SARIF
│   ├── sarif.py          # Parse SARIF → Violations
│   ├── semantic.py       # Build JudgmentRequests
│   ├── scorer.py         # Calculate score, level
│   ├── cache.py          # Project + global cache
│   ├── models.py         # Dataclasses
│   └── utils.py          # Shared helpers
├── bundled/
│   ├── capability-patterns.yml  # OpenGrep patterns for capability detection
│   └── levels.yml               # Level definitions and rule mappings
├── interfaces/
│   ├── cli/main.py       # Typer CLI entry point
│   └── mcp/
│       ├── server.py     # MCP server
│       └── tools.py      # Tool implementations
└── formatters/
    ├── json.py           # Canonical format
    ├── text.py           # CLI display
    └── mcp.py            # MCP wrapper
```

## Module Dependency Flow

```
interfaces/ (CLI, MCP)
     │
     ▼
engine.py (orchestration)
     │
     ├──► init.py ──► bootstrap.py
     │
     ├──► registry.py ──► bootstrap.py
     │
     ├──► applicability.py
     │
     ├──► discover.py
     │
     ├──► opengrep.py
     │
     ├──► sarif.py ──► models.py
     │
     ├──► semantic.py ──► models.py
     │
     ├──► scorer.py
     │
     └──► cache.py
            │
            ▼
      formatters/
```

---

## core/bootstrap.py

Path helpers and config loading. No I/O except config file reading.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `get_reporails_home()` | `Path` | `~/.reporails` directory |
| `get_opengrep_bin()` | `Path` | Path to OpenGrep binary |
| `get_rules_path()` | `Path` | `~/.reporails/rules/` |
| `get_core_rules_path()` | `Path` | `~/.reporails/rules/core/` |
| `get_agent_rules_path(agent)` | `Path` | `~/.reporails/rules/agents/{agent}/rules/` |
| `get_schemas_path()` | `Path` | `~/.reporails/rules/schemas/` |
| `get_version_file()` | `Path` | `~/.reporails/version` |
| `get_global_config()` | `GlobalConfig` | Load `~/.reporails/config.yml` |
| `is_initialized()` | `bool` | Check if OpenGrep + rules exist |
| `get_installed_version()` | `str | None` | Read version file |

**Constants:**

```python
REPORAILS_HOME = Path.home() / ".reporails"
FRAMEWORK_REPO = "reporails/reporails-rules"
FRAMEWORK_RELEASE_URL = f"https://github.com/{FRAMEWORK_REPO}/releases/download"
```

---

## core/agents.py

Agent definitions and detection. Supports multiple AI coding assistants.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `detect_agents(target)` | `list[DetectedAgent]` | Detect configured agents |
| `get_all_instruction_files(target)` | `list[Path]` | Get instruction files for all agents |
| `get_agent_type(agent_id)` | `AgentType` | Get agent definition |

**AgentType Definition:**

```python
@dataclass(frozen=True)
class AgentType:
    id: str                          # e.g., "claude"
    name: str                        # e.g., "Claude (Anthropic)"
    instruction_patterns: tuple[str, ...]  # Glob patterns
    config_patterns: tuple[str, ...]
    rule_patterns: tuple[str, ...]
```

**Known Agents:**

| Agent | Instruction Files | Rules Dir |
|-------|-------------------|-----------|
| claude | `CLAUDE.md`, `**/CLAUDE.md` | `.claude/rules/` |
| cursor | `.cursorrules`, `.cursor/rules/*.md` | `.cursor/rules/` |
| windsurf | `.windsurfrules` | — |
| copilot | `.github/copilot-instructions.md` | — |
| aider | `.aider.conf.yml`, `CONVENTIONS.md` | — |
| generic | `AGENTS.md`, `.ai/**/*.md` | `.ai/rules/` |

---

## core/levels.py

Level configuration and rule-to-level mapping. Loaded from bundled config.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `get_level_config()` | `LevelConfig` | Load bundled levels.yml |
| `get_rules_for_level(level)` | `set[str]` | Rule IDs required at level |
| `get_level_label(level)` | `str` | Human-readable label |
| `get_level_includes(level)` | `list[Level]` | Levels included (inheritance) |
| `detect_orphan_features(features, level)` | `bool` | Features above base level |

**Bundled Config (`bundled/levels.yml`):**

```yaml
levels:
  L1:
    name: Absent
    required_rules: []
  L2:
    name: Basic
    includes: [L1]
    required_rules: [S1, C1, C2, C4, C7, C8, C9, C10, C12, M5]
  L3:
    name: Structured
    includes: [L2]
    required_rules: [S2, S3, S7, C3, C6, C11, E6, E7, M1, M2]
  L4:
    name: Abstracted
    includes: [L3]
    required_rules: [S4, S5, E1, E3, E4, E5, E8, M7]
  L5:
    name: Governed
    includes: [L4]
    required_rules: [G1, G2, G3, G4, G8, M3, M4]
  L6:
    name: Adaptive
    includes: [L5]
    required_rules: [S6, C5, E2, G5, G6, G7, M6]

detection:
  L6: [has_backbone]
  L5: [component_count_3plus, has_shared_files]
  L4: [has_rules_dir]
  L3: [has_imports, has_multiple_instruction_files]
  L2: [has_instruction_file]
  L1: []
```

---

## core/init.py

Downloads OpenGrep binary and framework tarball on first run.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `run_init(force=False)` | `InitResult` | Full initialization |
| `ensure_initialized()` | `bool` | Check and init if needed |
| `download_opengrep()` | `Path` | Download binary for platform |
| `download_framework(version="latest")` | `Path` | Download and extract tarball |
| `get_latest_version()` | `str` | Fetch latest release tag from GitHub |
| `verify_checksum(file, expected)` | `bool` | Verify SHA256 |
| `get_platform_info()` | `tuple[str, str]` | Get OS and arch |

**Download Flow:**

```
1. Check ~/.reporails/version
2. If missing or outdated:
   a. Fetch latest release tag
   b. Download tarball from GitHub releases
   c. Verify checksum
   d. Extract to ~/.reporails/rules/
   e. Write version file
3. Return rules path
```

**Platform Support:**

| OS | Architecture | OpenGrep Binary |
|----|--------------|-----------------|
| Linux | x86_64 | opengrep-linux-x86_64 |
| Linux | aarch64 | opengrep-linux-aarch64 |
| macOS | x86_64 | opengrep-darwin-x86_64 |
| macOS | arm64 | opengrep-darwin-arm64 |
| Windows | x86_64 | opengrep-windows-x86_64.exe |

---

## core/registry.py

Loads rules from framework and resolves with project overrides.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `load_rules(agent, project_path)` | `dict[str, Rule]` | Load and resolve all rules |
| `load_framework_rules(agent)` | `dict[str, Rule]` | Load from `~/.reporails/rules/` |
| `load_project_overrides(project_path)` | `dict[str, Rule]` | Load from `.reporails/overrides/` |
| `load_project_rules(project_path)` | `dict[str, Rule]` | Load from `.reporails/rules/` |
| `load_project_config(project_path)` | `ProjectConfig` | Load `.reporails/config.yml` |
| `parse_rule_file(md_path)` | `Rule` | Parse frontmatter from .md |
| `find_yml_file(md_path)` | `Path | None` | Find matching .yml |
| `get_rules_by_type(rules, type)` | `dict[str, Rule]` | Filter by type (pure) |

**Resolution Order:**

```
1. ~/.reporails/rules/core/           # Framework core
2. ~/.reporails/rules/agents/{agent}/ # Framework agent
3. .reporails/overrides/              # Project overrides
4. .reporails/rules/                  # Project custom
5. Apply disabled_rules from config   # Remove disabled
```

---

## core/applicability.py

Detects project features (filesystem) and filters applicable rules.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `detect_features_filesystem(target)` | `DetectedFeatures` | Scan directories/files |
| `get_applicable_rules(rules, level)` | `dict[str, Rule]` | Filter rules by level |
| `get_feature_summary(features)` | `str` | Human-readable summary |

**Filesystem Detection:**

| Feature | Detection Method |
|---------|------------------|
| `has_instruction_file` | Any instruction file exists |
| `has_rules_dir` | `.claude/rules/`, `.cursor/rules/`, etc. |
| `has_shared_files` | `.shared/`, `shared/` exists |
| `has_backbone` | `.reporails/backbone.yml` exists |
| `component_count` | From discovery |
| `detected_agents` | From file patterns |

---

## core/capability.py

Detects content-based features (OpenGrep) and calculates capability score.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `detect_features_content(target)` | `ContentFeatures` | Run OpenGrep patterns |
| `calculate_capability_score(features)` | `int` | Weighted score (0-12) |
| `capability_score_to_level(score)` | `Level` | Map score to L1-L6 |
| `determine_capability_level(target)` | `Level` | Full detection pipeline |
| `get_capability_patterns_path()` | `Path` | Path to bundled patterns |

**Content Detection (OpenGrep):**

| Feature | Pattern |
|---------|---------|
| `has_sections` | `^##+ ` |
| `has_imports` | `@import\|@docs/\|@\.shared/` |
| `has_explicit_constraints` | `\bMUST\b\|\bMUST NOT\b\|\bNEVER\b` |
| `has_path_scoped_rules` | `^paths:\s*$` (in frontmatter) |

**Scoring:**

```python
CAPABILITY_WEIGHTS = {
    "has_instruction_file": 1,
    "has_sections": 1,
    "has_imports": 1,
    "has_explicit_constraints": 1,
    "has_rules_dir": 2,
    "has_path_scoped_rules": 1,
    "has_shared_files": 1,
    "component_count_3plus": 1,
    "has_backbone": 2,
}
# Max: 12 points
```

**Bundled Patterns:**

```
src/reporails_cli/
└── bundled/
    └── capability-patterns.yml
```

---

## core/discover.py

Finds instruction files and builds project map.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `discover_instruction_files(target)` | `list[Path]` | Find all instruction files |
| `run_discovery(target)` | `DiscoveryResult` | Full project analysis |
| `discover_components(target, files)` | `dict[str, Component]` | Build component hierarchy |
| `extract_references(content)` | `list[FileReference]` | Find file references in content |
| `generate_backbone_yaml(result)` | `str` | Generate backbone.yml content |
| `save_backbone(target, content)` | `Path` | Save to .reporails/ |

---

## core/engine.py

Orchestration only. Coordinates other modules.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `run_validation(target, agent, ...)` | `ValidationResult` | Full validation |
| `run_validation_sync(...)` | `ValidationResult` | Sync wrapper |

**Orchestration Flow:**

```python
async def run_validation(target: Path, agent: str = "claude", ...) -> ValidationResult:
    # 1. Ensure initialized
    ensure_initialized()
    
    # 2. Detect features
    features = detect_features(target)
    
    # 3. Load and resolve rules
    rules = load_rules(agent, target)
    applicable = get_applicable_rules(rules, features)
    
    # 4. Split by type
    deterministic = get_rules_by_type(applicable, RuleType.DETERMINISTIC)
    semantic = get_rules_by_type(applicable, RuleType.SEMANTIC)
    
    # 5. Run deterministic (OpenGrep)
    sarif = run_opengrep(deterministic, target)
    violations = parse_sarif(sarif, deterministic)
    
    # 6. Build semantic requests
    judgment_requests = build_semantic_requests(semantic, target)
    
    # 7. Calculate score
    score = calculate_score(len(applicable), violations)
    level = determine_capability_level(features)
    
    # 8. Return result
    return ValidationResult(...)
```

---

## core/opengrep.py

Runs OpenGrep binary. Isolated I/O.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `run_opengrep(config_paths, target)` | `dict` | Execute and return SARIF |
| `run_capability_detection(target)` | `dict` | Run bundled capability patterns |
| `run_rule_validation(rules, target)` | `dict` | Run rule .yml patterns |
| `build_temp_config(yml_paths)` | `Path` | Create merged temp config |
| `get_opengrep_command(config, target)` | `list[str]` | Build command args |

**Invocation Strategy:**

OpenGrep is invoked twice per validation:

1. **Capability detection** — bundled `capability-patterns.yml`
2. **Rule validation** — framework `.yml` files

This separation keeps capability logic (CLI concern) separate from rule logic (framework concern).

```
engine.py
    │
    ├──► run_capability_detection()  ──► capability-patterns.yml
    │           │
    │           ▼
    │    ContentFeatures
    │
    └──► run_rule_validation()  ──► rules/**/*.yml
                │
                ▼
         SARIF → Violations
```

---

## core/sarif.py

Parses SARIF output into domain objects. Pure functions.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `parse_sarif(sarif, rules)` | `list[Violation]` | Parse to violations |
| `extract_rule_id(sarif_rule_id)` | `str` | Extract short ID (e.g., "S1") |
| `extract_check_slug(sarif_rule_id)` | `str | None` | Extract check slug |
| `get_location(result)` | `str` | Format location string |
| `get_severity(rule, check_slug)` | `Severity` | Lookup severity |

---

## core/semantic.py

Builds JudgmentRequests for semantic rules. Pure functions.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `build_semantic_requests(rules, target)` | `list[JudgmentRequest]` | Build all requests |
| `build_request(rule, content, location)` | `JudgmentRequest` | Build single request |
| `extract_content_for_rule(rule, file_content)` | `str` | Get relevant content |

---

## core/scorer.py

Calculates scores. All pure functions.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `calculate_score(rules_checked, violations)` | `float` | Score on 0-10 scale |
| `determine_capability_level(features)` | `Level` | L1-L6 from features |
| `estimate_friction(violations)` | `FrictionEstimate` | Time waste estimate |
| `get_severity_weight(severity)` | `float` | Weight for scoring |
| `dedupe_violations(violations)` | `list[Violation]` | Remove duplicates |

**Scoring Formula:**

```
possible = rules_checked × DEFAULT_RULE_WEIGHT (2.5)
lost = sum(severity_weight for each unique violation)
earned = max(0, possible - lost)
score = (earned / possible) × 10
```

---

## core/cache.py

Project-local and global caching.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `ProjectCache.get_cached_files()` | `list[Path] | None` | Get cached file map |
| `ProjectCache.save_file_map(files)` | `None` | Cache file list |
| `ProjectCache.get_judgment(file, hash)` | `dict | None` | Get cached judgment |
| `ProjectCache.set_judgment(file, hash, result)` | `None` | Cache judgment |
| `record_scan(target, score, ...)` | `None` | Record to global analytics |

**Cache Locations:**

| Cache | Location | Purpose |
|-------|----------|---------|
| File map | `.reporails/.cache/file-map.json` | Skip filesystem scan |
| Judgments | `.reporails/.cache/judgment-cache.json` | Skip re-evaluation |
| Analytics | `~/.reporails/analytics/` | Global scan history |

---

## core/models.py

Dataclasses. Frozen where possible.

**Enums:**

- `Category`: structure, content, efficiency, governance, maintenance
- `RuleType`: deterministic, semantic
- `Severity`: critical, high, medium, low
- `Level`: L1, L2, L3, L4, L5, L6

**Dataclasses:**

- `Check`: id, name, severity
- `Rule`: id, title, category, type, checks, question, criteria, ...
- `Violation`: rule_id, location, message, severity, check_id
- `JudgmentRequest`: rule_id, content, question, criteria, ...
- `JudgmentResponse`: rule_id, verdict, reason, passed
- `ValidationResult`: score, level, violations, judgment_requests, ...
- `DetectedFeatures`: has_claude_md, has_rules_dir, ...
- `GlobalConfig`: framework_path, auto_update_check
- `ProjectConfig`: framework_version, disabled_rules, overrides

---

## core/utils.py

Shared helpers used across modules.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `parse_frontmatter(content)` | `dict` | Parse YAML frontmatter |
| `compute_content_hash(path)` | `str` | SHA256 hash of file |
| `is_valid_path_reference(path)` | `bool` | Check if path looks valid |
| `relative_to_safe(path, base)` | `str` | Safe relative path |

---

## interfaces/cli/main.py

Typer CLI application.

**Commands:**

| Command | Description |
|---------|-------------|
| `ails check [PATH]` | Validate instruction files |
| `ails check --format json` | Output as JSON |
| `ails check --refresh` | Force re-scan |
| `ails check --strict` | Exit 1 on violations (CI) |
| `ails check --quiet-semantic` | Suppress semantic message |
| `ails map [PATH]` | Discover project structure |
| `ails map --save` | Save backbone.yml |
| `ails explain RULE_ID` | Show rule details |
| `ails update` | Update framework |
| `ails version` | Show versions |

---

## interfaces/mcp/server.py

MCP server entry point.

**Tools:**

| Tool | Description |
|------|-------------|
| `validate` | Validate files, return violations + JudgmentRequests |
| `score` | Quick score check |
| `explain` | Get rule details |

---

## interfaces/mcp/tools.py

Tool implementations.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `validate_tool(path)` | `dict` | Run validation, format for MCP |
| `validate_tool_text(path)` | `str` | Run validation, text format |
| `score_tool(path)` | `dict` | Quick score |
| `explain_tool(rule_id)` | `dict` | Rule details |

---

## formatters/

Output adapters. Same interface, different formats.

**Interface:**

```python
def format_result(result: ValidationResult) -> T
def format_score(result: ValidationResult) -> T
def format_rule(rule_id: str, rule_data: dict) -> T
```

**Modules:**

| Module | Output | Notes |
|--------|--------|-------|
| `json.py` | `dict` | Canonical source of truth |
| `text.py` | `str` | CLI terminal display |
| `mcp.py` | `dict` | Wraps json.py, adds MCP instructions |

### text.py Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `format_result(result, ascii_mode, quiet_semantic)` | `str` | Full validation output |
| `format_compact(result, ascii_mode)` | `str` | Clean output for non-TTY |
| `format_score(result, ascii_mode)` | `str` | Score summary only |
| `format_rule(rule_id, rule_data)` | `str` | Rule explanation |
| `format_legend(ascii_mode)` | `str` | Severity legend |
| `format_violations(violations, ascii_mode)` | `str` | Violation list |
| `format_level_display(level, has_orphan)` | `str` | "L3" or "L3+" |

---

## Size Constraints

Per [Principle 7](principles.md#7-module-size-discipline):

| Module | Max Lines | Current | Status |
|--------|-----------|---------|--------|
| engine.py | 100 | 600+ | ❌ Split |
| registry.py | 150 | ~150 | ✓ |
| discover.py | 150 | ~250 | ❌ Trim |
| cache.py | 150 | ~200 | ⚠️ Review |
| scorer.py | 100 | ~150 | ⚠️ Review |
| main.py | 200 | ~300 | ⚠️ Review |
| All others | 100 | — | — |

---

## Related Docs

- [Architecture Overview](arch.md)
- [Architecture Principles](principles.md)
- [Data Models](models.md)
- [Scoring](scoring.md)
