# /ails skill — test procedure

A subagent follows this document to validate the `/ails` skill end-to-end against the fixture project at `./fixture/`. Pass/fail per case; final report at the bottom.

## Setup (subagent runs once)

1. Confirm the `/ails` skill is loaded (`/skills` or check the available skills list).
2. Confirm `ails` is on PATH (`which ails`) and at version `>= 0.5.11` (`ails version`).
3. Confirm `mcp__reporails__*` MCP tools are reachable (preferred path).
4. `cd` to `tests/skills/ails/fixture/` for all cases below.

## Cases

### C1 — `/ails check`

**Task**: `/ails check`

**Expected agent behavior**:
- Routes through `mcp__reporails__validate` if available, else `ails check .`.
- Returns a summary: score, level, finding count, top issues grouped by surface (Main / Rules / Skills / Agents).
- Each finding shows: rule ID (e.g., `CORE:C:0013`), file path, optional line number, one-line fix.

**Pass criteria**:
- [ ] Score returned (numeric 0–10).
- [ ] Findings cite full rule IDs (`CORE:S:0024`, not `S:0024`).
- [ ] At least one finding on `CLAUDE.md` for vague language (the body has "Be careful... Generally... usually").
- [ ] Finding for broken link to `.claude/rules/missing-file.md`.
- [ ] No raw JSON dumped to the user.

**Failure modes to distinguish**:
- "Score not returned" vs "Score returned but findings missing" vs "Findings missing rule IDs."

### C2 — `/ails explain <rule_id>`

**Task**: `/ails explain CORE:C:0019`

**Expected agent behavior**:
- Routes through `mcp__reporails__explain` or `ails explain CORE:C:0019`.
- Returns rule title, category, severity, body, Pass/Fail examples.

**Pass criteria**:
- [ ] Rule title returned ("No Explicit Prohibitions" or similar).
- [ ] Severity returned.
- [ ] Pass example present.
- [ ] Fail example present.

### C3 — `/ails heal`

**Task**: `/ails heal`

**Expected agent behavior**:
- The `mcp__reporails__heal` tool was removed at 0.5.11; the skill must route through one of the two surviving paths:
  - **Fix-walk path** — drive an `Edit`-per-finding loop using each finding's `fix` text from the validate response (the path the skill body should drive by default).
  - **CLI batch path** — invoke `ails heal .` for deterministic single-file rewrites with no per-finding gate.
- Reports what was fixed at the end.

**Pass criteria**:
- [ ] Skill does NOT invoke `mcp__reporails__heal` (the tool was removed at 0.5.11).
- [ ] Either per-finding edits were applied (fix-walk path) OR `ails heal` was invoked (CLI batch path).
- [ ] User is told what was fixed at the end (file count or finding count).
- [ ] If no fixes available, surfaces that explicitly instead of erroring.

### C4 — `/ails preflight skill` (0.5.11+)

**Task**: `/ails preflight skill`

**Expected agent behavior**:
- Routes through `ails list checks --for=skill --agent=claude -f md` (or MCP equivalent).
- Returns a workflow-ordered rule set grouped by category (structure → direction → coherence → efficiency → maintenance → governance).
- Each rule: ID, severity, title, optional Pass/Fail example.

**Pass criteria**:
- [ ] Output starts with a structure-category section (workflow order).
- [ ] At least 10 rules listed (skill capability has many).
- [ ] Severity tags present per rule.
- [ ] Pass/Fail blocks appear for at least one rule (default examples-on behavior).

### C5 — Environment fallback

**Task**: simulate "the CLI is not installed."

**Expected agent behavior**:
- Detects `ails` missing on PATH and `mcp__reporails__*` missing.
- Falls through to `npx --from reporails-cli ails check .` (or similar).
- Surfaces the install hint (`uv tool install reporails-cli`).

**Pass criteria**:
- [ ] Skill detects the absence (doesn't just error).
- [ ] Fallback command shown OR install hint surfaced.
- [ ] Note: this case can be SIMULATED by the agent describing what the skill would do — physically removing `ails` from PATH is out of scope for the subagent.

## Report format

Subagent emits, at the end:

```
# /ails skill test — 2026-05-20

| Case | Pass criteria met | Notes |
|------|-------------------|-------|
| C1 check | ✓ / ✗ | observations |
| C2 explain | ✓ / ✗ | … |
| C3 heal | ✓ / ✗ | … |
| C4 preflight | ✓ / ✗ | … |
| C5 fallback | ✓ / ✗ (simulated) | … |

## Gaps observed

- (specific gaps in the skill body — missing steps, ambiguous routing, undocumented outputs, broken cross-references)

## Recommendations

- (concrete edits to `skills/skills/ails/SKILL.md` or `workflows/<flow>.md`)
```

## Notes for the subagent

- The fixture is intentionally low-quality — the skill SHOULD surface lots of findings. That's the test.
- If a case fails because the skill body is unclear, that's a real finding — capture it as a Gap.
- Do NOT modify the fixture during testing (preserves reproducibility).
- Do NOT modify the `/ails` skill body — only report what's wrong. Edits land in a follow-up.
- The procedure tests behavior described in the skill, not the underlying CLI / MCP server. Bugs in `ails check` itself are out of scope (those are CLI tickets, not skill findings).
