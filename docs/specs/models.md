# Data Models

All models defined in `core/models.py`. Frozen (immutable) where possible.

## Enums

### Category
Rule categories: `STRUCTURE`, `CONTENT`, `MAINTENANCE`, `GOVERNANCE`, `EFFICIENCY`

### RuleType
Detection method: `DETERMINISTIC`, `HEURISTIC`, `SEMANTIC`

### Severity
Violation severity: `CRITICAL` (-25), `HIGH` (-15), `MEDIUM` (-10), `LOW` (-5)

### Level
Capability levels: `L1` through `L6`

## Dataclasses

### Antipattern
```
id: str              # e.g., "A3"
name: str            # e.g., "Root file > 200 lines"
severity: Severity
points: int          # Negative
```

### Rule
```
id: str              # e.g., "S1"
title: str           # e.g., "Size Limits"
category: Category
type: RuleType
level: str           # e.g., "L2+"
scoring: int

# Optional
detection: str | None
sources: list[int]
see_also: list[str]
antipatterns: list[Antipattern]
validation: str | None

# Paths (set after loading)
md_path: Path | None
yml_path: Path | None
```

### Violation
```
rule_id: str
rule_title: str
location: str        # e.g., "CLAUDE.md:45"
message: str
severity: Severity
points: int          # Negative
```

### JudgmentRequest
Request for host LLM to evaluate semantic rule:
```
rule_id: str
rule_title: str
content: str         # Text from CLAUDE.md
location: str
question: str
criteria: dict[str, str]
examples: dict[str, list[str]]
choices: list[str]
pass_value: str
severity: Severity
points_if_fail: int
```

### JudgmentResponse
```
rule_id: str
verdict: str         # One of the choices
reason: str
passed: bool         # verdict == pass_value
```

### ValidationResult
```
score: float         # 0.0-10.0 display scale
level: Level         # Capability level (determined by features)
violations: tuple[Violation, ...]
judgment_requests: tuple[JudgmentRequest, ...]
rules_checked: int
rules_passed: int
rules_failed: int
time_waste_estimate: dict[str, int]
feature_summary: str      # Human-readable detected features
violation_points: int     # Total deduction points
```
