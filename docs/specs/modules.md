# Module Specifications

## core/bootstrap.py

Path helpers for reporails home directory. No lazy downloading (see `init.py`).

**Functions:**
- `get_reporails_home()` → `Path` — Get `~/.reporails` directory
- `get_opengrep_bin()` → `Path` — Get path to OpenGrep binary
- `get_checks_path()` → `Path` — Get path to checks directory
- `is_initialized()` → `bool` — Check if opengrep + rules exist

## core/init.py

Downloads OpenGrep binary and rules on first run.

**Functions:**
- `run_init()` → `dict` — Download opengrep + rules, return status
- `download_opengrep()` → `Path` — Download OpenGrep binary
- `download_rules()` → `tuple[Path, int]` — Clone rules from framework repo, return (path, count)

**Platform Support:**

| OS | Architecture | Binary |
|----|--------------|--------|
| Linux | x86_64, aarch64 | opengrep-linux-* |
| macOS | x86_64, arm64 | opengrep-darwin-* |
| Windows | x86_64 | opengrep-windows-*.exe |

## core/registry.py

Loads rules from markdown frontmatter.

**Functions:**
- `load_rules(rules_dir)` → `dict[str, Rule]` — Load all rules from directory
- `parse_frontmatter(content)` → `dict` — Parse YAML frontmatter (pure)
- `build_rule(frontmatter, md_path, yml_path)` → `Rule` — Construct Rule object (pure)
- `get_rules_by_type(rules, rule_type)` → `dict[str, Rule]` — Filter by type (pure)

## core/engine.py

Runs OpenGrep and collects results. Orchestration only.

**Functions:**
- `run_validation(target, rules, opengrep_path)` → `ValidationResult` — Full validation
- `run_opengrep(yml_paths, target, opengrep_path)` → `dict` — Execute OpenGrep, return SARIF
- `parse_sarif(sarif, rules)` → `list[Violation]` — Parse SARIF output (pure)
- `prepare_semantic_requests(rules, content, file_path)` → `list[JudgmentRequest]` — Build LLM requests (pure)

## core/scorer.py

Calculates scores from violations. All pure functions.

**Functions:**
- `calculate_score(rules_checked, violations)` → `float` — Weighted score on 0.0-10.0 scale
- `calculate_weighted_score(rules_checked, violations)` → `float` — Implementation of weighted scoring
- `has_critical_violations(violations)` → `bool` — Check for critical severity
- `determine_capability_level(features)` → `Level` — Determine L1-L6 from detected features (purely feature-based)
- `estimate_time_waste(violations)` → `dict[str, int]` — Minutes by category
- `get_severity_points(severity)` → `int` — Point deduction for severity (legacy)

**Constants:**
- `SEVERITY_WEIGHTS` — Scoring weights: Critical=5.5, High=4.0, Medium=2.5, Low=1.0
- `DEFAULT_RULE_WEIGHT` — Default weight per rule (2.5)

## interfaces/mcp/server.py

MCP server entry point.

**Tools:**
- `validate` — Validate CLAUDE.md files, return violations + JudgmentRequests
- `score` — Quick score check
- `explain` — Get rule details by ID

## interfaces/cli/main.py

Typer CLI application.

**Commands:**
- `check [PATH]` — Validate with format option (text/json)
- `map [PATH]` — Discover project structure, generate backbone.yml
- `explain RULE_ID` — Show rule details

## formatters/

Output adapters with consistent interface.

**Interface:** Each formatter exports:
- `format_result(result: ValidationResult) -> T`
- `format_score(result: ValidationResult) -> T`
- `format_rule(rule_id: str, rule_data: dict) -> T`

Where `T` is `dict` for json/mcp, `str` for text.

**Modules:**
- `json.py` — Canonical dict (source of truth)
- `mcp.py` — MCP output (wraps json, allows MCP-specific transforms)
- `text.py` — CLI terminal display
