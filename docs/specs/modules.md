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
│   ├── applicability.py  # Feature detection (filesystem)
│   ├── capability.py     # Capability scoring (OpenGrep)
│   ├── discover.py       # Find instruction files
│   ├── engine.py         # Orchestration only (~170 lines)
│   ├── opengrep/         # OpenGrep execution (package)
│   │   ├── __init__.py   # Public API re-exports
│   │   ├── runner.py     # Binary execution, sync only
│   │   ├── templates.py  # {{placeholder}} resolution
│   │   └── semgrepignore.py  # .semgrepignore handling
│   ├── sarif.py          # Parse SARIF → Violations
│   ├── semantic.py       # Build JudgmentRequests
│   ├── scorer.py         # Calculate score, level
│   ├── cache.py          # Project + global cache, analytics
│   ├── models.py         # Dataclasses
│   └── utils.py          # Shared helpers
├── bundled/
│   ├── capability-patterns.yml  # OpenGrep patterns for capability detection
│   └── levels.yml               # Level definitions and rule mappings
├── templates/            # CLI output templates
│   └── __init__.py       # Template loader (load_template, render)
├── interfaces/
│   ├── cli/main.py       # Typer CLI entry point
│   └── mcp/
│       ├── server.py     # MCP server
│       └── tools.py      # Tool implementations (sync)
└── formatters/
    ├── json.py           # Canonical format
    ├── text/             # CLI display (package)
    │   ├── __init__.py   # Public API re-exports
    │   ├── full.py       # Full terminal output
    │   ├── compact.py    # Non-TTY output
    │   ├── box.py        # Assessment box formatting
    │   ├── violations.py # Violations section
    │   ├── components.py # Shared helpers
    │   ├── chars.py      # Unicode/ASCII character sets
    │   └── rules.py      # Rule explanation
    └── mcp.py            # MCP wrapper
```

## Module Dependency Flow

```
interfaces/ (CLI, MCP)
     │
     ▼
engine.py (orchestration, sync)
     │
     ├──► init.py ──► bootstrap.py
     │
     ├──► registry.py ──► bootstrap.py
     │
     ├──► applicability.py
     │
     ├──► discover.py
     │
     ├──► opengrep/ (package)
     │       ├── runner.py
     │       ├── templates.py
     │       └── semgrepignore.py
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
      formatters/ ──► templates/
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
| `get_agent_config(agent)` | `AgentConfig` | Load agent excludes + overrides from framework config |
| `get_global_config()` | `GlobalConfig` | Load `~/.reporails/config.yml` |
| `get_project_config(project_root)` | `ProjectConfig` | Load `.reporails/config.yml` from project |
| `get_package_paths(project_root, packages)` | `list[Path]` | Resolve package names to `.reporails/packages/<name>/` dirs |
| `get_package_level_rules(project_root, packages)` | `dict[str, list[str]]` | Load and merge level→rules mappings from package `levels.yml` files |
| `is_initialized()` | `bool` | Check if OpenGrep + rules exist |
| `get_installed_version()` | `str | None` | Read version file |

**Constants:**

```python
REPORAILS_HOME = Path.home() / ".reporails"
```

---

## core/levels.py

Level configuration and rule-to-level mapping. Loaded from bundled config.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `get_level_config()` | `LevelConfig` | Load bundled levels.yml |
| `get_rules_for_level(level, extra_level_rules=None)` | `set[str]` | Rule IDs required at level (with optional package extras) |
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

Downloads OpenGrep binary and framework rules tarball on first run. Handles updates.

**Constants:**

```python
OPENGREP_VERSION = "1.15.1"
RULES_VERSION = "0.2.1"
RULES_TARBALL_URL = "https://github.com/reporails/rules/releases/download/{version}/reporails-rules-{version}.tar.gz"
RULES_API_URL = "https://api.github.com/repos/reporails/rules/releases/latest"
```

**Dataclasses:**

- `UpdateResult`: previous_version, new_version, updated, rule_count, message

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `run_init()` | `dict` | Full initialization (OpenGrep + rules) |
| `download_opengrep()` | `Path` | Download binary for platform |
| `download_rules()` | `tuple[Path, int]` | Download rules (local or GitHub) |
| `download_from_github()` | `tuple[Path, int]` | Download from GitHub release tarball |
| `download_rules_tarball(dest)` | `int` | Download and extract tarball |
| `download_rules_version(version)` | `tuple[Path, int]` | Download rules for specific version |
| `copy_bundled_yml_files(dest)` | `int` | Copy bundled .yml files |
| `copy_local_framework(source)` | `tuple[Path, int]` | Copy from local path (dev mode) |
| `get_platform()` | `tuple[str, str]` | Get OS and arch |
| `get_latest_version()` | `str \| None` | Fetch latest version from GitHub API |
| `update_rules(version, force)` | `UpdateResult` | Update rules to version (or latest) |
| `write_version_file(version)` | `None` | Write version to ~/.reporails/version |

**Download Flow:**

```
1. Download OpenGrep binary for platform
2. Setup rules:
   a. Check for local framework_path override (dev mode)
   b. If local: copy from local path
   c. Otherwise: download from GitHub release tarball
3. Merge bundled .yml files with downloaded rules
4. Write version file
5. Return results dict
```

**Update Flow:**

```
1. Check for dev mode (local framework_path)
2. Determine target version (specified or fetch latest)
3. Check current installed version
4. Skip if already at target (unless --force)
5. Download and extract rules tarball
6. Write version file
7. Return UpdateResult
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

Loads rules from framework and project packages, applies tier filtering and disabled_rules.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `load_rules(rules_dir, include_experimental, project_root, agent)` | `dict[str, Rule]` | Load and resolve all rules |
| `get_experimental_rules(rules_dir)` | `dict[str, Rule]` | Get experimental-tier rules (for skip reporting) |
| `build_rule(frontmatter, md_path, yml_path)` | `Rule` | Build Rule from parsed frontmatter (pure) |
| `derive_tier(backed_by)` | `Tier` | Derive core/experimental from source weights |
| `get_rules_by_type(rules, type)` | `dict[str, Rule]` | Filter by type (pure) |
| `get_rules_by_category(rules, category)` | `dict[str, Rule]` | Filter by category (pure) |
| `get_rule_yml_paths(rules)` | `list[Path]` | Get .yml paths for rules |

**Resolution Order:**

```
1. ~/.reporails/rules/core/              # Framework core
2. ~/.reporails/rules/agents/            # Framework agent
3. Agent excludes (remove rule IDs)
4. Agent overrides (adjust check severity, disable checks)
5. .reporails/packages/<name>/           # Project packages (override by rule ID)
6. Filter: tier (core vs experimental)
7. Filter: disabled_rules removal
```

---

## core/applicability.py

Detects project features (filesystem) and filters applicable rules.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `detect_features_filesystem(target)` | `DetectedFeatures` | Scan directories/files |
| `get_applicable_rules(rules, level, extra_level_rules=None)` | `dict[str, Rule]` | Filter rules by level (with optional package extras) |
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

Orchestration only. Coordinates other modules. ~170 lines.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `run_validation(target, agent, ...)` | `ValidationResult` | Full validation (sync) |
| `run_validation_sync(...)` | `ValidationResult` | Legacy alias for `run_validation` |

**Orchestration Flow:**

```python
def run_validation(target: Path, agent: str = "claude", ...) -> ValidationResult:
    # 1. Auto-init if needed
    if not is_initialized():
        run_init()

    # 2. Auto-create backbone if missing
    if not backbone_path.exists():
        save_backbone(project_root, generate_backbone_yaml(run_discovery(project_root)))

    # 3. Phase 1: Filesystem feature detection
    features = detect_features_filesystem(project_root)

    # 4. Load rules, estimate preliminary level for filtering
    rules = load_rules(rules_dir)
    prelim_level = estimate_preliminary_level(features)
    applicable = get_applicable_rules(rules, prelim_level)

    # 5. Single consolidated OpenGrep invocation
    #    - Capability patterns + applicable rule patterns
    combined_sarif = run_opengrep(all_yml_paths, target, template_context=get_agent_vars(agent))

    # 6. Phase 2: Content feature detection from SARIF
    content_features = detect_features_content(combined_sarif)
    capability = determine_capability_level(features, content_features)

    # 7. Parse violations, build semantic requests
    violations = parse_sarif(combined_sarif, deterministic_rules)
    judgment_requests = build_semantic_requests(combined_sarif, semantic_rules, target)

    # 8. Calculate score, friction
    score = calculate_score(len(applicable), dedupe_violations(violations))
    friction = estimate_friction(violations)

    # 9. Record analytics, return result
    record_scan(target, score, capability.level.value, ...)
    return ValidationResult(
        score=score,
        level=capability.level,
        violations=tuple(violations),
        judgment_requests=tuple(judgment_requests),
        is_partial=bool(judgment_requests),
        pending_semantic=PendingSemantic(...) if judgment_requests else None,
        ...
    )
```

---

## core/opengrep/ (package)

Runs OpenGrep binary. Isolated I/O. Sync-only (async removed in v0.1.0).

### Package Structure

```
core/opengrep/
├── __init__.py       # Public API re-exports (34 lines)
├── runner.py         # Binary execution (203 lines)
├── templates.py      # {{placeholder}} resolution (138 lines)
└── semgrepignore.py  # .semgrepignore handling (39 lines)
```

### Public API (`__init__.py`)

| Function | Returns | Description |
|----------|---------|-------------|
| `run_opengrep(yml_paths, target, opengrep_path, template_context)` | `dict` | Execute and return SARIF |
| `run_capability_detection(target)` | `dict` | Run bundled capability patterns |
| `run_rule_validation(rules, target)` | `dict` | Run rule .yml patterns |
| `get_rule_yml_paths(rules)` | `list[Path]` | Get existing .yml paths |
| `set_debug_timing(enabled)` | `None` | Enable/disable timing output |
| `has_templates(yml_path)` | `bool` | Check for {{placeholder}} |
| `resolve_templates(yml_path, context)` | `str` | Resolve template placeholders |

### Template Resolution (`templates.py`)

Handles `{{placeholder}}` substitution in .yml rule configs:

- **Array context** (paths.include): Expands list to multiple items
- **Regex context** (pattern-regex): Converts globs to regex, joins with `|`
- **Scalar context**: Simple string substitution

### Invocation Strategy

Engine makes **single consolidated OpenGrep invocation**:

```
engine.py
    │
    └──► run_opengrep(all_yml_paths, target, template_context)
                │
                ├── capability-patterns.yml (bundled)
                └── applicable rule .yml files (framework)
                │
                ▼
         Combined SARIF output
                │
                ├──► detect_features_content() → ContentFeatures
                └──► parse_sarif() → Violations
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
| `estimate_friction(violations)` | `FrictionEstimate` | Friction level from severity counts |
| `get_severity_weight(severity)` | `float` | Weight for scoring |
| `dedupe_violations(violations)` | `list[Violation]` | Remove duplicates |
| `get_level_label(level)` | `str` | Human-readable label |
| `has_critical_violations(violations)` | `bool` | Check for critical violations |

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
- `AgentConfig`: agent, excludes, overrides
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
| `ails update` | Update framework to latest |
| `ails update --version VERSION` | Update to specific version |
| `ails update --check` | Check for updates without installing |
| `ails update --force` | Force reinstall even if current |
| `ails version` | Show CLI and framework versions |

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

## templates/

CLI output template system. Uses simple `{variable}` substitution.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `load_template(name)` | `str` | Load template file by name |
| `render(name, **kwargs)` | `str` | Load and render template with variables |
| `render_conditional(name, condition, **kwargs)` | `str` | Render only if condition true |

**Template Files:**

```
templates/
├── __init__.py           # Template loader
├── cli_box.txt           # Assessment box
├── cli_violation.txt     # Single violation line
├── cli_file_header.txt   # File header with count
├── cli_pending.txt       # Pending semantic section
├── cli_cta.txt           # MCP call-to-action
├── cli_legend.txt        # Severity legend
└── cli_working.txt       # "What's working" section
```

**Usage:**

```python
from reporails_cli.templates import render

output = render("cli_violation.txt",
    icon="●",
    rule_id="S1.root-too-long",
    line="45",
    message="Root file exceeds 200 lines",
)
```

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
| `text/` | `str` | CLI terminal display (package) |
| `mcp.py` | `dict` | Wraps json.py, adds MCP instructions |

### text/ Package

Refactored from single file to package for maintainability:

```
formatters/text/
├── __init__.py       # Public API re-exports (28 lines)
├── full.py           # Full terminal output (136 lines)
├── compact.py        # Non-TTY output (121 lines)
├── box.py            # Assessment box formatting (89 lines)
├── violations.py     # Violations section (92 lines)
├── components.py     # Shared helpers (117 lines)
├── chars.py          # Unicode/ASCII character sets (42 lines)
└── rules.py          # Rule explanation (50 lines)
```

**Public API (`text/__init__.py`):**

| Function | Returns | Description |
|----------|---------|-------------|
| `format_result(result, ascii_mode, quiet_semantic, show_legend, delta)` | `str` | Full validation output |
| `format_compact(result, ascii_mode, delta)` | `str` | Clean output for non-TTY |
| `format_score(result, ascii_mode, delta)` | `str` | Score summary only |
| `format_rule(rule_id, rule_data)` | `str` | Rule explanation |
| `format_legend(ascii_mode)` | `str` | Severity legend |

**Delta Display:**

All formatters accept optional `ScanDelta` parameter to show improvement/regression indicators:
- Score: `↑ +1.5` or `↓ -0.5`
- Level: `(was L3)` when changed
- Violations: `(-2)` or `(+3)`

---

## Size Constraints

Per [Principle 7](principles.md#7-module-size-discipline):

| Module | Max Lines | Current | Status |
|--------|-----------|---------|--------|
| engine.py | 200 | 173 | ✓ |
| registry.py | 150 | 155 | ✓ |
| discover.py | 400 | 362 | ✓ |
| cache.py | 400 | 352 | ✓ |
| scorer.py | 200 | 182 | ✓ |
| main.py | 250 | ~200 | ✓ |
| opengrep/runner.py | 250 | 203 | ✓ |
| opengrep/templates.py | 150 | 138 | ✓ |
| text/compact.py | 150 | 121 | ✓ |
| text/full.py | 150 | 136 | ✓ |
| All others | 150 | — | — |

---

## Related Docs

- [Architecture Overview](arch.md)
- [Architecture Principles](principles.md)
- [Data Models](models.md)
- [Scoring](scoring.md)
