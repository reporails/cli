# Scoring System

Score calculation, capability levels, time waste estimation, and semantic rules.

## Two Independent Metrics

**Score** and **Level** are separate concepts:

- **Score (0-10)**: Quality/compliance — how well you follow the rules that apply to your setup
- **Level (L1-L6)**: Capability tier — what features your setup has (determined by detected features)

A simple CLAUDE.md project (L2) can score 10/10 if it follows all L2 rules perfectly.

## Score Calculation

**0-10 scale** with weighted pass-rate scoring. Score reflects the percentage of "possible points" earned after accounting for violation weights.

**Formula:** `Score = (earned / possible) × 10`

- `possible = rules_checked × 2.5` (default weight per rule)
- `earned = possible - violation_weights` (floored at 0)
- Violations are deduplicated by (file, rule_id) before scoring

### Severity Weights

Higher severity = higher weight = more impact on score.

| Severity | Weight | OpenGrep Level |
|----------|--------|----------------|
| Critical | 5.5 | `error` |
| High | 4.0 | `warning` |
| Medium | 2.5 | `warning` |
| Low | 1.0 | `warning` |
| Info | 0 (skipped) | `note` |

**Example:** 10 rules checked, 1 critical violation
- Possible: 10 × 2.5 = 25 points
- Lost: 5.5 (one critical)
- Earned: 25 - 5.5 = 19.5
- Score: (19.5 / 25) × 10 = **7.8**

This rewards passing rules rather than only punishing violations.

### Capability Levels

See [Capability Levels](../capability-levels.md) for detailed level descriptions.

Level is determined **purely by features detected**, not by score:

| Level | Required Features | Label |
|-------|-------------------|-------|
| L6 | backbone.yml | Adaptive |
| L5 | 3+ components or shared files | Governed |
| L4 | `.claude/rules/` directory | Modular |
| L3 | @imports or multiple instruction files | Structured |
| L2 | CLAUDE.md exists | Basic |
| L1 | No CLAUDE.md | Absent |

Different levels fit different projects. L3 is ideal for solo projects; L6 fits complex monorepos.

### Visual Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   SCORE: 9.2 / 10  |  CAPABILITY: Modular                    ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░         ║
║                                                              ║
║   Setup: 3 instruction files, .claude/rules/                 ║
║                                                              ║
║   2 violation(s) · 25 rules checked                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

## Friction Estimation

Estimates rework time from **re-explanation loops** and **redo cycles** caused by poor instructions.

**Display:** `Friction: High (est. ~37 min rework)`

### Friction Levels

| Level | Total Time | Meaning |
|-------|------------|---------|
| High | ≥20 min | Significant rework expected |
| Medium | 10-19 min | Moderate rework |
| Low | 5-9 min | Minor friction |

### Time per Severity

| Severity | Time | Description |
|----------|------|-------------|
| Critical | 5 min | Clarification loop + partial redo |
| High | 3 min | Clarification loop |
| Medium | 2 min | Brief clarification |
| Low | 1 min | Minor friction |

## Rule Detection Types

Rules are classified by detection method, optimizing for accuracy and cost:

| Type | Count | Detection Method | Output |
|------|-------|------------------|--------|
| Deterministic | 20 | OpenGrep pattern → direct result | `Violation` |
| Heuristic | 12 | OpenGrep gate → LLM confirmation | `JudgmentRequest` |
| Semantic | 6 | LLM judgment only | `JudgmentRequest` |

### Deterministic Rules

100% certainty via OpenGrep pattern matching. Match = violation.

### Heuristic Rules (Two-Stage Filter)

Minimizes LLM cost with pattern gating:

```
OpenGrep pattern match (gate)
    │
    ├── No match → Pass (95% of files, zero LLM cost)
    │
    └── Match → JudgmentRequest
                    │
                    └── LLM evaluates question + criteria
                            │
                            ├── Confirmed → Violation
                            └── Dismissed → Pass
```

Each heuristic rule has:
- `detection`: OpenGrep pattern that gates LLM calls
- `question`: What to ask when pattern matches
- `criteria`: Pass/fail definition

### Semantic Rules

6 rules require LLM judgment with no pattern gate (defined in `semantic/definitions.py`):
- C2, C8, E2, G3, M1, S3

These always generate `JudgmentRequest` objects for host LLM evaluation.

## Related Docs

- [Architecture Overview](arch.md)
- [Data Models](models.md) — `Violation`, `JudgmentRequest` definitions
- [Module Specifications](modules.md) — `scorer.py` functions
