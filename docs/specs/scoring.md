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

Level is determined by **weighted feature scoring**, not by quality score.

### Feature Weights

| Signal | Points | Detection Method |
|--------|--------|------------------|
| Has instruction file | +1 | File existence (any agent) |
| Has sections/headers | +1 | Markdown H2+ detection |
| Has @imports or file references | +1 | Regex for paths, @import |
| Has explicit constraints (MUST/NEVER) | +1 | Keyword detection |
| Has rules directory | +2 | `.claude/rules/`, `.cursor/rules/`, etc. |
| Has path-scoped rules (frontmatter) | +1 | YAML frontmatter with `paths:` |
| Has shared files | +1 | `.shared/`, `shared/`, cross-references |
| Component count ≥ 3 | +1 | Discovery analysis |
| Has backbone/manifest | +2 | `.reporails/backbone.yml` |

**Max possible: 12 points**

### Score → Level Mapping

| Capability Score | Level | Label |
|------------------|-------|-------|
| 0 | L1 | Absent |
| 1-2 | L2 | Basic |
| 3-4 | L3 | Structured |
| 5-6 | L4 | Abstracted |
| 7-9 | L5 | Governed |
| 10+ | L6 | Adaptive |

### Detection Pipeline

Capability detection runs in two phases:

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
│  Scoring                                │
│  - calculate_capability_score()         │
│  - capability_score_to_level()          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
            Level (L1-L6)
```

### Detection Logic

```python
def determine_capability_level(target: Path) -> CapabilityResult:
    # Phase 1: Filesystem detection
    features = detect_features_filesystem(target)
    
    # Phase 2: Content detection (OpenGrep)
    content_features = detect_features_content(target)
    
    # Merge content features into main features
    features.has_sections = content_features.has_sections
    features.has_imports = content_features.has_imports
    features.has_explicit_constraints = content_features.has_explicit_constraints
    features.has_path_scoped_rules = content_features.has_path_scoped_rules
    
    # Calculate score and level
    score = calculate_capability_score(features)
    level = capability_score_to_level(score)
    
    # Check for orphan features (features above base level)
    has_orphan = detect_orphan_features(features, level)
    
    summary = get_feature_summary(features)
    
    return CapabilityResult(
        features=features,
        capability_score=score,
        level=level,
        has_orphan_features=has_orphan,
        feature_summary=summary,
    )


def calculate_capability_score(features: DetectedFeatures) -> int:
    score = 0
    
    # Phase 1 features (filesystem)
    if features.has_instruction_file:
        score += 1
    if features.has_rules_dir:
        score += 2
    if features.has_shared_files:
        score += 1
    if features.component_count >= 3:
        score += 1
    if features.has_backbone:
        score += 2
    
    # Phase 2 features (content)
    if features.has_sections:
        score += 1
    if features.has_imports:
        score += 1
    if features.has_explicit_constraints:
        score += 1
    if features.has_path_scoped_rules:
        score += 1
    
    return score


def capability_score_to_level(score: int) -> Level:
    if score >= 10:
        return Level.L6
    if score >= 7:
        return Level.L5
    if score >= 5:
        return Level.L4
    if score >= 3:
        return Level.L3
    if score >= 1:
        return Level.L2
    return Level.L1


def detect_orphan_features(features: DetectedFeatures, base_level: Level) -> bool:
    """Check if project has features from levels above base level.
    
    Example: L3 project with backbone.yml (L6 feature) → has_orphan = True
    Display as "L3+" to indicate advanced features present.
    """
    level_features = {
        Level.L6: [features.has_backbone],
        Level.L5: [features.component_count >= 3, features.has_shared_files],
        Level.L4: [features.has_rules_dir],
        Level.L3: [features.has_imports],
    }
    
    level_order = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]
    base_index = level_order.index(base_level)
    
    # Check features from levels above base
    for level in level_order[base_index + 1:]:
        if level in level_features:
            if any(level_features[level]):
                return True
    
    return False
```

### Level Labels

```python
LEVEL_LABELS = {
    Level.L1: "Absent",
    Level.L2: "Basic",
    Level.L3: "Structured",
    Level.L4: "Abstracted",
    Level.L5: "Governed",
    Level.L6: "Adaptive",
}
```

### Agent-Agnostic Detection

Rules directory detection supports multiple agents:

```python
RULES_DIR_PATTERNS = [
    ".claude/rules/",
    ".cursor/rules/",
    ".ai/rules/",
]

INSTRUCTION_FILE_PATTERNS = [
    "CLAUDE.md",
    "AGENTS.md", 
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
    "CONVENTIONS.md",
]
```

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

Two rule types with different detection methods:

| Type | Detection | LLM Required | Output |
|------|-----------|--------------|--------|
| **Deterministic** | OpenGrep pattern | No | `Violation` |
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