# Capability Levels

Capability levels describe what your AI instruction setup enables — not how "mature" it is. Different projects need different capabilities. L3 is perfect for a solo project; L6 fits complex monorepos.

## 6-Level Scale

| Level | Name | What It Enables | Key Indicators |
|-------|------|-----------------|----------------|
| **L1** | Absent | No AI instructions | Missing or unmodified `/init` output |
| **L2** | Basic | Single-file instructions | 30-200 lines, stack + commands + constraints |
| **L3** | Structured | External references, organized content | @imports, < 200 lines root |
| **L4** | Modular | Path-scoped rules, context-aware loading | .claude/rules/, hierarchical memory |
| **L5** | Governed | Team policies, compliance tracking | Org policies deployed, metrics |
| **L6** | Adaptive | Map-driven navigation, contracts | YAML backbone, component-contract binding |

> **Note:** L1-L4 patterns are documented in official sources. L5-L6 patterns are derived from enterprise software practices.

---

## Level Descriptions

### Level 1: Absent/Generated
- No CLAUDE.md file, or unreviewed `/init` output
- Contains auto-detected info (often wrong or redundant)
- **Risk:** Inconsistent behavior, wasted tokens on irrelevant context
- **Fix:** Review and customize within 30 minutes
- **Primary rules:** None (file doesn't exist or isn't functional)

### Level 2: Basic
- Contains core sections: stack, commands, constraints
- 30-200 lines, may include code style rules (antipattern)
- Version controlled but no @imports
- **Risk:** Token bloat, instruction dilution as file grows
- **Fix:** Extract details to @imports, remove code style rules
- **Primary rules:** [S1](rules/structure/S1-size-limits.md), [C1](rules/content/C1-core-sections.md), [C2](rules/content/C2-explicit-over-implicit.md), [C4](rules/content/C4-anti-pattern-documentation.md), [C7](rules/content/C7-emphasis-discipline.md), [C8](rules/content/C8-instructions-over-philosophy.md), [C9](rules/content/C9-has-project-description.md), [C10](rules/content/C10-has-never-statements.md), [C12](rules/content/C12-has-version-date.md), [M5](rules/maintenance/M5-auto-generated-content-review.md)

### Level 3: Structured
- Uses @imports to external documentation
- Root file focuses on pointers, not content
- No embedded code snippets
- Clear markdown structure with headings
- **Risk:** Import references may become stale
- **Fix:** Implement .claude/rules/ for path-scoped loading
- **Primary rules:** [S2](rules/structure/S2-progressive-disclosure.md), [S3](rules/structure/S3-no-embedded-code-snippets.md), [S7](rules/structure/S7-clear-markdown-structure.md), [C3](rules/content/C3-context-specific-content.md), [C6](rules/content/C6-single-source-of-truth.md), [C11](rules/content/C11-links-are-valid.md), [E6](rules/efficiency/E6-code-block-line-limit.md), [E7](rules/efficiency/E7-import-count.md), [M1](rules/maintenance/M1-version-control.md), [M2](rules/maintenance/M2-review-process.md)

### Level 4: Modular
- Implements .claude/rules/ directory
- Path-scoped rules for different code areas
- Hooks handle formatting/linting
- Root file < 100 lines
- CLAUDE.local.md for personal preferences
- **Risk:** Complexity if not well-documented
- **Fix:** Add governance processes for enterprise scale
- **Primary rules:** [S4](rules/structure/S4-hierarchical-memory.md), [S5](rules/structure/S5-path-scoped-rules.md), [E1](rules/efficiency/E1-deterministic-tools-for-style.md), [E3](rules/efficiency/E3-purpose-based-file-reading.md), [E4](rules/efficiency/E4-memory-reference.md), [E5](rules/efficiency/E5-grep-efficiency.md), [E8](rules/efficiency/E8-context-window-awareness.md), [M7](rules/maintenance/M7-rule-snippet-length-enforcement.md)

### Level 5: Governed
- Organization-level policies deployed
- All changes go through PR review
- Metrics dashboard tracking compliance
- Automated CI/CD checks
- ROI documented
- **Risk:** Process overhead if not automated
- **Fix:** Add navigation maps for complex codebases
- **Primary rules:** [G1](rules/governance/G1-organization-level-policies.md)-[G4](rules/governance/G4-ownership-assignment.md), [G8](rules/governance/G8-metrics-and-cicd-checks.md), [M3](rules/maintenance/M3-change-management.md)-[M4](rules/maintenance/M4-no-conflicting-rules.md)

### Level 6: Adaptive
- YAML backbone (`.reporails/backbone.yml`) as complete path index
- Navigation maps for components, platform, contracts
- Session start ritual: read maps before searching
- Component-contract binding for segment-aware loading
- MUST/MUST NOT rule format with source traceability
- Architecture tests enforce contracts
- **Risk:** Map staleness; requires maintenance discipline
- **Applicability:** See "When to Use Level 6" below
- **Primary rules:** [S6](rules/structure/S6-yaml-backbone.md), [C5](rules/content/C5-must-must-not-with-context.md), [E2](rules/efficiency/E2-session-start-ritual.md), [G5](rules/governance/G5-contract-registry.md)-[G7](rules/governance/G7-architecture-tests.md), [M6](rules/maintenance/M6-map-staleness-prevention.md)

---

## When to Use Level 6

**Appropriate when:**
- Monorepo with 3+ distinct components
- Hexagonal or layered architecture with enforced boundaries
- Multiple developers needing consistent context loading
- Codebase > 50k lines with distinct domains

**Overkill when:**
- Single-component projects
- Solo developer projects
- Simple CRUD applications
- Codebases < 10k lines

---

## Capability Assessment Matrix

| Criteria | Rule | L1 | L2 | L3 | L4 | L5 | L6 |
|----------|------|----|----|----|----|----|----|
| File exists | — | - | + | + | + | + | + |
| Manually reviewed | M5 | - | + | + | + | + | + |
| Core sections present | C1 | - | + | + | + | + | + |
| Explicit instructions | C2 | - | + | + | + | + | + |
| Antipatterns documented | C4 | - | + | + | + | + | + |
| Emphasis discipline | C7 | - | + | + | + | + | + |
| Instructions not philosophy | C8 | - | + | + | + | + | + |
| Project description | C9 | - | + | + | + | + | + |
| Has NEVER statements | C10 | - | + | + | + | + | + |
| Has version/date | C12 | - | + | + | + | + | + |
| Size limits | S1 | - | + | + | + | + | + |
| Uses @imports | S2 | - | - | + | + | + | + |
| No code snippets | S3 | - | - | + | + | + | + |
| Clear markdown structure | S7 | - | - | + | + | + | + |
| Context-specific content | C3 | - | - | + | + | + | + |
| Single source of truth | C6 | - | - | + | + | + | + |
| Links valid | C11 | - | - | + | + | + | + |
| Code block limit | E6 | - | - | + | + | + | + |
| Import count | E7 | - | - | + | + | + | + |
| Version controlled | M1 | - | - | + | + | + | + |
| Review process | M2 | - | - | + | + | + | + |
| .claude/rules/ used | S4 | - | - | - | + | + | + |
| Path-scoped rules | S5 | - | - | - | + | + | + |
| Deterministic tools | E1 | - | - | - | + | + | + |
| Purpose-based reading | E3 | - | - | - | + | + | + |
| Memory reference | E4 | - | - | - | + | + | + |
| Grep efficiency | E5 | - | - | - | + | + | + |
| Context window awareness | E8 | - | - | - | + | + | + |
| Rule snippet length | M7 | - | - | - | + | + | + |
| Org policies deployed | G1 | - | - | - | - | + | + |
| Team governance | G2 | - | - | - | - | + | + |
| Security rules ownership | G3 | - | - | - | - | + | + |
| Ownership assignment | G4 | - | - | - | - | + | + |
| Metrics/CI checks | G8 | - | - | - | - | + | + |
| Change management | M3 | - | - | - | - | + | + |
| No conflicting rules | M4 | - | - | - | - | + | + |
| YAML backbone | S6 | - | - | - | - | - | + |
| MUST/MUST NOT format | C5 | - | - | - | - | - | + |
| Session start ritual | E2 | - | - | - | - | - | + |
| Contract registry | G5 | - | - | - | - | - | + |
| Component-contract binding | G6 | - | - | - | - | - | + |
| Architecture tests | G7 | - | - | - | - | - | + |
| Map staleness prevention | M6 | - | - | - | - | - | + |

**Legend:** `+` Required | `-` Not expected

---

## Level Progression

| Transition | Key Actions | Effort |
|------------|-------------|--------|
| L1 → L2 | Review /init output, add core sections | 1-2 hours |
| L2 → L3 | Extract to @imports, remove code style rules | 2-4 hours |
| L3 → L4 | Implement .claude/rules/, configure hooks | 1-2 days |
| L4 → L5 | Deploy org policies, build metrics dashboard | 2-4 weeks |
| L5 → L6 | Design YAML backbone, implement contract registry | 4-8 weeks |

---

## Recommended Levels by Context

| Context | Target | Rationale |
|---------|--------|-----------|
| Solo developer | L3 | Structure without overhead |
| Small team (2-5) | L3-L4 | Shared standards, modular ownership |
| Medium team (6-20) | L4 | Full optimization |
| Large team (20+) | L5 | Governance required |
| Complex monorepo | L6 | Map-driven navigation essential |
| Platform/SDK teams | L6 | Contract enforcement needed |

---

## Assessment Scoring

### Quick Assessment (5 minutes)

| Check | Rule | Pass |
|-------|------|------|
| File exists and manually reviewed | M5 | Y/N |
| < 200 lines | S1 | Y/N |
| Has project context (1-liner) | C9 | Y/N |
| Has commands section | C1 | Y/N |
| No embedded code snippets | S3 | Y/N |
| No code style rules | E1 | Y/N |
| Version controlled | M1 | Y/N |

**Score:** 7/7 = L2+, < 5/7 = L1

### Deep Validation Checklist

Quick Assessment checks presence. This checklist validates quality and patterns.

| Check | Rule | How to Verify |
|-------|------|---------------|
| NEVER statements have alternatives | C10 | Each NEVER followed by "—" or "instead" or positive action |
| Commands use tool syntax, not bash | E5 | Commands section uses `Grep`/`Read` tool patterns, not raw `grep`/`cat` |
| Commands are context-appropriate | C3 | No references to non-existent paths (e.g., `node_modules` in non-JS repo) |
| @imports point to existing files | C11 | All `@path` references resolve to actual files |
| Efficiency rules apply to examples | E5 | Documented commands follow same rules as AI behavior |
| MUST/MUST NOT have context | C5 | Each rule includes source or rationale in parentheses |
| No stale references | M6 | Map paths match actual file structure |

**When to use:** After Quick Assessment passes, before declaring a level.

### Full Assessment Rubric

| Category | Max | Criteria | Rules |
|----------|-----|----------|-------|
| Structure | 20 | Lines < 100 (+10), < 200 (+5); @imports (+5); headings (+5) | [S rules](rules/structure/) |
| Content | 35 | Universal (+10); Specific (+10); Antipatterns (+10); Description (+5) | [C rules](rules/content/) |
| Maintenance | 15 | Version control (+5); Review process (+5); No conflicts (+5) | [M rules](rules/maintenance/) |
| Governance | 15 | Org policy (+5); Security rules (+5); Ownership (+5) | [G rules](rules/governance/) |
| Efficiency | 15 | No linting (+5); Disclosure (+5); Code block limit (+5) | [E rules](rules/efficiency/) |

**Total: /100**

| Score | Grade | Level |
|-------|-------|-------|
| 90-100 | A | L5-L6 |
| 80-89 | B | L4 |
| 70-79 | C | L3 |
| 50-69 | D | L2 |
| < 50 | F | L1 |

---

## Sources

| Concept | Primary Sources |
|---------|-----------------|
| Maturity model structure | [23] CMMI Maturity Levels, [24] Cloud Native Maturity Model |
| L1-L2 basics | [1] Claude Code Best Practices, [6] Using CLAUDE.md Files |
| L3 @imports | [2] Memory Documentation, [10] Monorepo case study |
| L4 .claude/rules/ | [4] Settings, [15] Rules Directory Mechanics |
| L5 governance | [7] How Anthropic Teams Use Claude Code, [13] Enterprise patterns |
| L6 map-first | [25] Reporails Empirical Data |
| Assessment criteria | [9] Issue #13579, [12] Optimization study |

See [README.md Sources & References](README.md#sources--references) for full citations.
