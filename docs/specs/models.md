# Data Models

All models defined in `core/models.py`. Frozen (immutable) where possible.

## Enums

### Category

Rule categories matching framework.

```python
class Category(str, Enum):
    STRUCTURE = "structure"
    CONTENT = "content"
    EFFICIENCY = "efficiency"
    GOVERNANCE = "governance"
    MAINTENANCE = "maintenance"
```

### RuleType

Detection method. Two types only.

```python
class RuleType(str, Enum):
    DETERMINISTIC = "deterministic"  # OpenGrep pattern → direct violation
    SEMANTIC = "semantic"            # LLM judgment required
```

### Severity

Violation severity levels with scoring weights.

```python
class Severity(str, Enum):
    CRITICAL = "critical"  # Weight: 5.5
    HIGH = "high"          # Weight: 4.0
    MEDIUM = "medium"      # Weight: 2.5
    LOW = "low"            # Weight: 1.0
```

### Level

Capability levels from framework.

```python
class Level(str, Enum):
    L1 = "L1"  # Absent
    L2 = "L2"  # Basic
    L3 = "L3"  # Structured
    L4 = "L4"  # Abstracted
    L5 = "L5"  # Governed
    L6 = "L6"  # Adaptive
```

---

## Core Dataclasses

### Check

A specific check within a rule. Maps to OpenGrep pattern.

```python
@dataclass(frozen=True)
class Check:
    id: str          # e.g., "S1-root-too-long"
    name: str        # e.g., "Root file exceeds 200 lines"
    severity: Severity
```

### Rule

A rule definition loaded from framework frontmatter.

```python
@dataclass
class Rule:
    # Required (from frontmatter)
    id: str              # e.g., "S1"
    title: str           # e.g., "Size Limits"
    category: Category
    type: RuleType
    level: Level         # Minimum level this rule applies to
    
    # Checks (deterministic rules)
    checks: list[Check] = field(default_factory=list)
    
    # Semantic fields (semantic rules)
    question: str | None = None
    criteria: list[dict] | None = None  # [{key, check}, ...]
    choices: list[dict] | None = None   # [{value, label}, ...]
    pass_value: str | None = None
    examples: dict | None = None        # {good: [...], bad: [...]}
    
    # References
    sources: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)
    
    # Paths (set after loading)
    md_path: Path | None = None
    yml_path: Path | None = None
```

### Violation

A rule violation found during analysis.

```python
@dataclass(frozen=True)
class Violation:
    rule_id: str         # e.g., "S1"
    rule_title: str      # e.g., "Size Limits"
    location: str        # e.g., "CLAUDE.md:45"
    message: str         # From OpenGrep
    severity: Severity
    check_id: str | None = None  # e.g., "S1-root-too-long"
```

### JudgmentRequest

Request for host LLM to evaluate semantic rule.

```python
@dataclass(frozen=True)
class JudgmentRequest:
    rule_id: str
    rule_title: str
    content: str         # Text to evaluate
    location: str        # e.g., "CLAUDE.md"
    question: str        # What to evaluate
    criteria: list[dict] # [{key, check}, ...]
    choices: list[dict]  # [{value, label}, ...]
    pass_value: str      # Which choice means "pass"
    examples: dict       # {good: [...], bad: [...]}
    severity: Severity
    points_if_fail: int
```

### JudgmentResponse

Response from host LLM after evaluation.

```python
@dataclass(frozen=True)
class JudgmentResponse:
    rule_id: str
    verdict: str    # One of the choice values
    reason: str     # Explanation
    passed: bool    # verdict == pass_value
```

### ValidationResult

Complete validation output.

```python
@dataclass(frozen=True)
class ValidationResult:
    score: float                              # 0.0-10.0 scale
    level: Level                              # Capability level
    violations: tuple[Violation, ...]         # Immutable
    judgment_requests: tuple[JudgmentRequest, ...]
    rules_checked: int                        # Deterministic rules checked
    rules_pending: int                        # Semantic rules pending
    rules_passed: int
    rules_failed: int
    feature_summary: str                      # Human-readable
    friction: FrictionEstimate
```

---

## Feature Detection

### DetectedFeatures

Features detected in a project for capability scoring. Populated in two phases, then frozen.

**Note:** This is a mutable dataclass during construction. After both phases complete, treat as immutable.

```python
@dataclass
class DetectedFeatures:
    # === Phase 1: Filesystem detection (applicability.py) ===
    
    # Base existence
    has_instruction_file: bool = False       # Any instruction file found
    
    # Directory structure
    has_rules_dir: bool = False              # .claude/rules/, .cursor/rules/, etc.
    has_shared_files: bool = False           # .shared/, shared/, cross-refs
    has_backbone: bool = False               # .reporails/backbone.yml
    
    # Discovery
    component_count: int = 0                 # Components from discovery
    instruction_file_count: int = 0
    detected_agents: list[str] = field(default_factory=list)
    
    # === Phase 2: Content detection (capability.py via OpenGrep) ===
    
    # Content analysis
    has_sections: bool = False               # Has H2+ headers
    has_imports: bool = False                # @imports or file references
    has_explicit_constraints: bool = False   # MUST/NEVER keywords
    has_path_scoped_rules: bool = False      # Rules with paths: frontmatter
```

### ContentFeatures

Intermediate result from OpenGrep content analysis.

```python
@dataclass(frozen=True)
class ContentFeatures:
    has_sections: bool = False
    has_imports: bool = False
    has_explicit_constraints: bool = False
    has_path_scoped_rules: bool = False
```

### CapabilityResult

Result of capability detection pipeline.

```python
@dataclass(frozen=True)
class CapabilityResult:
    features: DetectedFeatures
    capability_score: int          # 0-12
    level: Level                   # Base level (L1-L6)
    has_orphan_features: bool      # Has features above base level (display as L3+)
    feature_summary: str           # Human-readable
```

### FrictionEstimate

Time waste estimate from violations.

```python
@dataclass(frozen=True)
class FrictionEstimate:
    level: str           # "high", "medium", "low", "none"
    total_minutes: int
    by_category: dict[str, int]  # {"S": 5, "C": 3, ...}
```

---

## Configuration

### GlobalConfig

Global user configuration (`~/.reporails/config.yml`).

```python
@dataclass
class GlobalConfig:
    framework_path: Path | None = None   # Local override (dev)
    auto_update_check: bool = True
```

### ProjectConfig

Project-level configuration (`.reporails/config.yml`).

```python
@dataclass
class ProjectConfig:
    framework_version: str | None = None  # Pin version
    disabled_rules: list[str] = field(default_factory=list)
    overrides: dict[str, dict] = field(default_factory=dict)
```

---

## Discovery

### Component

A discovered component (directory with instruction files).

```python
@dataclass
class Component:
    id: str              # Dot-separated: "app.agents"
    root: Path
    instruction_files: list[Path] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    parent: str | None = None
    content_hash: str | None = None
```

### DiscoveryResult

Result of discovery operation.

```python
@dataclass
class DiscoveryResult:
    target: Path
    discovered_at: str
    agents: list[DetectedAgent]
    components: dict[str, Component]
    shared_files: list[str]
    total_instruction_files: int
    total_references: int
```

---

## Init / Update

### InitResult

Result of initialization.

```python
@dataclass
class InitResult:
    success: bool
    opengrep_path: Path | None
    rules_path: Path | None
    framework_version: str | None
    errors: list[str] = field(default_factory=list)
```

### UpdateResult

Result of framework update.

```python
@dataclass
class UpdateResult:
    success: bool
    message: str
    old_version: str | None = None
    new_version: str | None = None
```

---

## Migration from Old Schema

| Old | New | Notes |
|-----|-----|-------|
| `Antipattern` | `Check` | Renamed |
| `antipatterns: list[Antipattern]` | `checks: list[Check]` | Field renamed |
| `RuleType.HEURISTIC` | Removed | Only deterministic + semantic |
| `points: int` | Removed from Check | Calculated from severity weight |
| `criteria: str` | `criteria: list[dict]` | Structured format |
| `choices: list[str]` | `choices: list[dict]` | Value + label |

---

## Related Docs

- [Architecture Overview](arch.md)
- [Module Specifications](modules.md)
- [Scoring](scoring.md)
