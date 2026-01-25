# Testing Specification

Test design decisions and invariants for the reporails CLI.

## Philosophy

Tests exist to catch bugs before users do. We prioritize:

1. **Correctness over coverage** — 80% coverage with wrong assertions is worthless
2. **Real execution over mocks** — Mock semgrep and you'll miss semgrep bugs
3. **Failure clarity** — A failing test must explain what broke and why
4. **Regression prevention** — Every bug fixed gets a test that would have caught it

---

## Test Categories

### Critical Path (blocks release)

Tests that verify core functionality. If these fail, the CLI is broken.

| Area | What it tests | Test file |
|------|---------------|-----------|
| Template resolution | `{{instruction_files}}` → actual paths | `test_template_resolution.py` |
| Rule validation | Valid rules accepted, invalid rejected | `test_rule_validation.py` |
| Exit codes | Semgrep exit codes interpreted correctly | `test_exit_codes.py` |
| Scoring | Same input → same score | `test_scoring.py` |
| Level detection | Correct L1-L6 assignment | `test_capability_detection.py` |

### Regression Tests

Tests added because something broke. Marked with `# regression: <description>`.

| Bug | Test | File |
|-----|------|------|
| `pattern-not-regex` at top level invalid | `test_toplevel_pattern_not_regex_rejected` | `test_rule_validation.py` |
| Empty dict `{}` is falsy in Python | `test_empty_context_skips_resolution` | `test_template_resolution.py` |
| Exit code 7 caused silent failure | `test_cli_handles_exit_7_gracefully` | `test_exit_codes.py` |
| Unresolved templates reach semgrep | `test_literal_template_never_reaches_opengrep` | `test_template_resolution.py` |

### Integration Tests

Tests that run real OpenGrep on real (fixture) repos.

- All `test_capability_detection.py` tests run actual OpenGrep
- All `test_rule_validation.py` tests run actual OpenGrep
- No mocking of the semgrep/opengrep binary

### Edge Cases

Boundary conditions and error handling.

| Case | Expected behavior |
|------|-------------------|
| Empty directory | L1 level, no error |
| Missing CLAUDE.md | L1 level, no error |
| No files match rule paths | No findings, no error |
| All rules invalid | Empty results, warning logged |
| Zero rules checked | Valid score (not division by zero) |
| 100+ violations | Score ≥ 0 (not negative) |

---

## Fixtures

### Fixture Repos

Created dynamically via pytest fixtures in `conftest.py`:

| Fixture | Structure | Tests |
|---------|-----------|-------|
| `level1_project` | Just `CLAUDE.md` | Minimal detection |
| `level2_project` | `CLAUDE.md` with sections, MUST/NEVER | Basic features |
| `level3_project` | + `.claude/rules/` | Rules directory detection |
| `level5_project` | + `.reporails/backbone.yml` | Full governed setup |
| `temp_project` | Minimal throwaway | General testing |

### Fixture Rules

YAML rule fixtures for testing validation:

| Fixture | Purpose |
|---------|---------|
| `valid_rule_yaml` | Simple valid rule (pattern-regex) |
| `valid_rule_with_patterns_yaml` | Valid rule using patterns: block |
| `invalid_toplevel_pattern_not_regex_yaml` | Invalid schema (regression test) |
| `rule_with_template_yaml` | Contains `{{instruction_files}}` |
| `rule_with_unresolvable_template_yaml` | Contains `{{nonexistent}}` |

---

## Template Resolution Contract

**The most critical invariant in the system:**

> No template variable (e.g., `{{instruction_files}}`) may reach semgrep unresolved.

### What MUST be true

- [ ] `get_agent_vars("claude")` returns dict with `instruction_files` key
- [ ] `resolve_yml_templates()` replaces all known placeholders
- [ ] `has_templates()` correctly identifies files needing resolution
- [ ] `run_opengrep()` writes resolved content to temp file before execution
- [ ] Unresolved templates cause clear errors or empty results (not silent wrong behavior)

### Template Flow

```
Rule file: paths.include: ["{{instruction_files}}"]
           │
           ▼
get_agent_vars("claude") → {"instruction_files": "**/CLAUDE.md", ...}
           │
           ▼
has_templates(yml_path) → True
           │
           ▼
resolve_yml_templates(yml_path, context) → paths.include: ["**/CLAUDE.md"]
           │
           ▼
Write to temp file → /tmp/xxx/rule.yml
           │
           ▼
opengrep scan --config /tmp/xxx/rule.yml
```

### Tests

```python
# Must pass
test_instruction_files_resolves_to_glob
test_resolve_yml_templates_replaces_placeholders
test_run_opengrep_resolves_templates_before_execution

# Must catch problems
test_literal_template_never_reaches_opengrep  # regression
test_empty_context_skips_resolution           # regression
```

---

## Exit Code Contract

OpenGrep/Semgrep exit codes and how the CLI handles them:

| Exit Code | Meaning | CLI Behavior | Test |
|-----------|---------|--------------|------|
| 0 | Success, scan completed | Return SARIF results | `test_exit_0_no_findings` |
| 1 | Findings exist (with --error flag) | Return SARIF results | `test_exit_1_with_error_flag_and_findings` |
| 2 | CLI usage error | Should not occur (we control args) | — |
| 7 | Invalid configuration | Log warning, return empty runs | `test_exit_7_invalid_config` |

### Key invariants

- "No findings" is NOT an error
- "No files matched" is NOT an error
- Exit code 7 should not crash the CLI
- Errors should surface to user (not silently swallowed)

### Tests

```python
test_cli_treats_exit_0_as_success
test_cli_treats_exit_1_as_success_with_findings
test_cli_handles_exit_7_gracefully
test_no_findings_is_not_error
test_no_files_matched_is_not_error
```

---

## Scoring Invariants

### Determinism

- Same violations → same score (always)
- Violation order does not affect score
- Multiple runs on same project → same score

### Bounds

- Score ∈ [0.0, 10.0]
- No violations → 10.0
- Score never negative (even with 100+ violations)
- Zero rules checked → valid score (not NaN/crash)

### Formula

```
possible = rules_checked × 2.5
lost = sum(severity_weight for each unique violation)
earned = max(0, possible - lost)
score = (earned / possible) × 10
```

### Severity Weights

| Severity | Weight | Score Impact |
|----------|--------|--------------|
| Critical | 5.5 | Major |
| High | 4.0 | Significant |
| Medium | 2.5 | Moderate |
| Low | 1.0 | Minor |

### Tests

```python
test_no_violations_perfect_score
test_violations_reduce_score
test_more_violations_lower_score
test_higher_severity_more_impact
test_same_violations_same_score
test_violation_order_does_not_affect_score
test_score_minimum_zero
test_score_maximum_ten
test_score_zero_rules_checked
```

---

## Capability Detection Invariants

### Detection is deterministic

- Same project structure → same level (always)
- Same capability score → same level (always)

### Missing files lower level, never error

- No CLAUDE.md → L1 (not error)
- No rules dir → lower score (not error)
- No backbone → lower score (not error)

### Orphan features flagged, not error

Orphan feature = advanced feature in basic project (e.g., backbone.yml in L2 project)

- Detection: Check if features from higher levels are present
- Display: Show as "L3+" to indicate advanced features
- Not an error condition

### Level Detection Criteria

See [scoring.md](scoring.md) for full details.

| Level | Key Signals |
|-------|-------------|
| L1 | Nothing detected |
| L2 | Has instruction file |
| L3 | Has sections, imports |
| L4 | Has rules directory |
| L5 | Has shared files, 3+ components |
| L6 | Has backbone.yml |

### Tests

```python
test_level1_minimal_project
test_level2_basic_project
test_level3_structured_project
test_level5_governed_project
test_missing_files_lowers_level
test_same_project_same_level
test_same_score_same_level
```

---

## Running Tests

```bash
# Full suite
uv run pytest tests/ -v

# Shorter output (CI mode)
uv run pytest tests/ -v --tb=short

# Specific test file
uv run pytest tests/test_template_resolution.py -v

# Specific test class
uv run pytest tests/test_scoring.py::TestScoreDeterminism -v

# Specific test
uv run pytest tests/test_rule_validation.py::TestOpenGrepSchemaValidation::test_toplevel_pattern_not_regex_rejected -v

# Show print output
uv run pytest tests/ -v -s
```

### CI Requirements

- All tests must pass
- Tests must not require network access (except OpenGrep binary, pre-installed)
- Tests must complete in < 5 minutes total
- No flaky tests (if it fails intermittently, fix it or remove it)

---

## Adding Tests

### When fixing a bug

1. Write a test that fails without the fix
2. Apply the fix
3. Verify test passes
4. Add comment: `# regression: <description of original bug>`

```python
def test_toplevel_pattern_not_regex_rejected(self, ...):
    """pattern-not-regex at top level is INVALID and must be rejected.

    regression: This was the root cause of the "6 invalid rules" issue.
    pattern-not-regex requires a patterns: block wrapper.
    """
    ...
```

### When adding features

1. Write tests for expected behavior first
2. Include at least one negative test (what should NOT happen)
3. Test error messages, not just error occurrence

### Test structure

```python
def test_descriptive_name(self, fixture1, fixture2):
    """One-line description of what this tests.

    Optional: longer explanation if needed.
    regression: <if this is a regression test>
    """
    # Arrange
    ...

    # Act
    result = function_under_test(...)

    # Assert with clear failure message
    assert result == expected, (
        f"Expected X but got Y because Z\n"
        f"Input: {input}\n"
        f"Output: {result}"
    )
```

---

## Test File Organization

```
tests/
├── conftest.py                    # Fixtures and helpers
├── fixtures/                      # Static fixture files (if needed)
├── test_template_resolution.py    # Template variable handling
├── test_rule_validation.py        # OpenGrep schema validation
├── test_exit_codes.py             # Exit code interpretation
├── test_capability_detection.py   # Level detection
└── test_scoring.py                # Score calculation
```

### Naming conventions

- Test files: `test_<area>.py`
- Test classes: `Test<Area><Aspect>`
- Test methods: `test_<what>_<expected_behavior>`

---

## What We Don't Test

- OpenGrep internals (that's their responsibility)
- Specific rule content (framework's responsibility)
- Network operations (OpenGrep download tested separately)
- MCP protocol compliance (tested via MCP tools)

---

## Related Docs

- [Architecture Overview](arch.md) — system structure
- [Architecture Principles](principles.md) — design principles (testability)
- [Module Specifications](modules.md) — module boundaries (test at boundaries)
- [Scoring](scoring.md) — scoring logic and invariants
- [Data Models](models.md) — dataclass definitions
