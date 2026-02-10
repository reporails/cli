# Scoring System

Score calculation, capability levels, and friction estimation.

## Two Independent Metrics

**Score** and **Level** are separate concepts:

| Metric | Measures | Range | Determined by |
|--------|----------|-------|---------------|
| **Score** | Quality/compliance | 0-10 | Violations found |
| **Level** | Capability tier | L1-L6 | Features detected |

A simple CLAUDE.md project (L2) can score 10/10 if it follows all applicable rules perfectly.

---

## Score Calculation

**0-10 scale** with weighted pass-rate scoring.

### Formula

```
possible = rules_checked × DEFAULT_RULE_WEIGHT
lost = sum(severity_weight for each unique violation)
earned = max(0, possible - lost)
score = (earned / possible) × 10
```

### Constants

```python
DEFAULT_RULE_WEIGHT = 2.5

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 5.5,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
}
```

### Example

10 rules checked, 1 critical violation:

```
possible = 10 × 2.5 = 25 points
lost = 5.5 (one critical)
earned = 25 - 5.5 = 19.5
score = (19.5 / 25) × 10 = 7.8
```

### Deduplication

Violations are deduplicated by `(file, rule_id)` before scoring. Same rule violation in same file counts once.

---

## Capability Levels

Level is determined by **capability gates**, not by quality score.

### Gate-Based Detection

Each level defines a set of capabilities (from framework `registry/levels.yml`). Detection uses a **cumulative ladder**: OR within each level, AND across levels.

A project is at the highest level where ALL levels L1 through N have at least one detected capability.

### Level → Capabilities

| Level | Label | Capabilities (OR) |
|-------|-------|--------------------|
| L0 | Absent | (none) |
| L1 | Basic | `instruction_file` |
| L2 | Scoped | `project_constraints`, `size_controlled` |
| L3 | Structured | `external_references`, `multiple_files` |
| L4 | Abstracted | `path_scoping` |
| L5 | Maintained | `structural_integrity`, `org_policy`, `navigation` |
| L6 | Adaptive | `dynamic_context`, `extensibility`, `state_persistence` |

**Source**: Framework `registry/levels.yml` with CLI fallback mapping.

### Capability Detectors (CLI-owned)

| Capability | Detection |
|------------|-----------|
| `instruction_file` | Any instruction file exists |
| `project_constraints` | Has explicit constraints (MUST/NEVER) — content-based |
| `size_controlled` | Root instruction file under size threshold |
| `external_references` | Has @imports or file references |
| `multiple_files` | Has multiple instruction files |
| `path_scoping` | Has path-scoped rules or is abstracted — content-based |
| `structural_integrity` | Not filesystem-detectable (always False) |
| `org_policy` | Has shared files (.shared/, shared/) |
| `navigation` | Has backbone or component count >= 3 |
| `dynamic_context` | Has .claude/skills/ directory |
| `extensibility` | Has MCP config |
| `state_persistence` | Has memory directory |

### Detection Pipeline

```
┌─────────────────────────────────────────┐
│  Phase 1: Filesystem (applicability.py) │
│  - File/directory existence             │
│  - Discovery analysis                   │
└─────────────────┬───────────────────────┘
                  │
                  ▼
         DetectedFeatures (partial)
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Phase 2: Content (capability.py)       │
│  - OpenGrep pattern matching            │
│  - Bundled capability-patterns.yml      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
         DetectedFeatures (complete)
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Gate Walking (levels.py)               │
│  - Load capabilities from registry      │
│  - Walk L6→L1, find highest passing     │
│  - determine_level_from_gates()         │
└─────────────────┬───────────────────────┘
                  │
                  ▼
            Level (L0-L6)
```

### Detection Logic

```python
def determine_level_from_gates(features: DetectedFeatures, skip_content: bool = False) -> Level:
    level_caps = _load_level_capabilities()  # From registry/levels.yml

    # Walk from L6 down to L1, find highest where all cumulative levels pass
    for level in reversed(_LEVEL_ORDER):
        if _all_levels_pass(features, level, level_caps, skip_content):
            return level

    return Level.L0


def _all_levels_pass(features, target_level, level_caps, skip_content) -> bool:
    """Check if all levels from L1 through target have at least one capability."""
    target_index = _LEVEL_ORDER.index(target_level)
    for lvl in _LEVEL_ORDER[:target_index + 1]:
        if not _level_has_capability(features, lvl.value, level_caps, skip_content):
            return False
    return True


def _level_has_capability(features, level_key, level_caps, skip_content) -> bool:
    """Check if at least one capability at this level is detected (OR)."""
    capabilities = level_caps.get(level_key, [])
    if not capabilities:
        return True  # Level with no capabilities = passing
    return any(_detect_capability(features, cap_id, skip_content) for cap_id in capabilities)
```

### Orphan Features

When a project has capabilities from levels above its base level (e.g., L3 project with skills directory), it's displayed as "L3+" to indicate advanced features are present but cumulative gates weren't met.

---

## Rule Applicability

Rules specify minimum level in frontmatter. Rules apply at their level and above.

| Rule Level | Applies to |
|------------|------------|
| `L2` | L2, L3, L4, L5, L6 |
| `L3` | L3, L4, L5, L6 |
| `L4` | L4, L5, L6 |
| `L5` | L5, L6 |
| `L6` | L6 only |

### Filtering Logic

```python
def get_applicable_rules(rules: dict[str, Rule], level: Level) -> dict[str, Rule]:
    """Filter rules to those applicable at the given level.
    
    Rules apply at their minimum level and above.
    """
    level_order = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]
    detected_index = level_order.index(level)
    
    applicable = {}
    for rule_id, rule in rules.items():
        rule_index = level_order.index(rule.level)
        if rule_index <= detected_index:
            applicable[rule_id] = rule
    
    return applicable
```

---

## Friction Estimation

Estimates friction from violations based on severity counts.

### Friction Levels

| Level | Criteria | Meaning |
|-------|----------|---------|
| Extreme | Any critical violation | Severe issues requiring immediate attention |
| High | 2+ high severity OR 5+ violations | Significant friction expected |
| Medium | 1 high severity OR 3-4 violations | Moderate friction |
| Small | 1-2 violations (medium/low) | Minor friction |
| None | No violations | No friction |

### Calculation

```python
def estimate_friction(violations: list[Violation]) -> FrictionEstimate:
    unique = dedupe_violations(violations)

    if not unique:
        return FrictionEstimate(level="none")

    critical_count = sum(1 for v in unique if v.severity == Severity.CRITICAL)
    high_count = sum(1 for v in unique if v.severity == Severity.HIGH)
    total_count = len(unique)

    if critical_count > 0:
        level = "extreme"
    elif high_count >= 2 or total_count >= 5:
        level = "high"
    elif high_count >= 1 or total_count >= 3:
        level = "medium"
    else:
        level = "small"

    return FrictionEstimate(level=level)
```

---

## Rule Types

Three rule types with different detection methods:

| Type | Detection | LLM Required | Output |
|------|-----------|--------------|--------|
| **Deterministic** | OpenGrep pattern | No | `Violation` |
| **Mechanical** | Python structural check | No | `Violation` |
| **Semantic** | Content extraction | Yes | `JudgmentRequest` |

### Deterministic Flow

```
OpenGrep runs .yml patterns
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
Runner scans rule checks array
        │
        ▼
  Filter type="mechanical"
        │
        ▼
  Dispatch to Python function
  (file_exists, line_count, etc.)
        │
        ▼
    CheckResult
        │
    ┌───┴───┐
  Pass     Fail (respects negate)
            │
            ▼
        Violation
```

**Mechanical checks** are Python-native structural checks for things OpenGrep cannot detect (file existence, directory structure, byte sizes, import depth). Any rule type may contain mechanical checks — the runner filters by `check.type` internally.

Available checks: `file_exists`, `directory_exists`, `directory_contains`, `git_tracked`, `frontmatter_key`, `file_count`, `line_count`, `byte_size`, `path_resolves`, `extract_imports`, `aggregate_byte_size`, `import_depth`, `directory_file_types`, `frontmatter_valid_glob`, `content_absent`.

### Semantic Flow

```
Engine extracts content
        │
        ▼
  Build JudgmentRequest
  (question, criteria, choices)
        │
        ▼
  Return to host (MCP/CLI)
        │
        ▼
  Host LLM evaluates (MCP only)
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

**Note:** CLI builds JudgmentRequests but does not execute them. It reports "X semantic rules pending." MCP provides instructions for the host LLM to evaluate inline.

---

## Visual Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   SCORE: 9.2 / 10  |  CAPABILITY: Abstracted                 ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░         ║
║                                                              ║
║   Setup: 3 instruction files, .claude/rules/                 ║
║                                                              ║
║   2 violation(s) · 25 rules checked                          ║
║   Friction: Small                                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Related Docs

- [Architecture Overview](arch.md)
- [Module Specifications](modules.md) — `scorer.py` functions
- [Data Models](models.md) — `Violation`, `FrictionEstimate` definitions