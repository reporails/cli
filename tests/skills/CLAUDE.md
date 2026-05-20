# tests/skills/

Manual subagent procedures for validating shipped `reporails` skills against deliberately-imperfect fixtures. This subtree is NOT a `pytest` suite — running `uv run poe test_unit` or `uv run poe test_integration` does not exercise these files.

## Layout

```text
tests/skills/
├── CLAUDE.md            # this file
└── <skill>/             # one directory per skill under test
    ├── test-procedure.md
    └── fixture/
        ├── CLAUDE.md
        └── .claude/...
```

Each `tests/skills/<skill>/` directory carries one `test-procedure.md` (step-by-step the subagent follows) plus one `fixture/` tree (the project root the procedure scans). The fixture is low-quality on purpose so the skill has real findings to surface.

## How a run works

A subagent loaded with the target skill `cd`s to `tests/skills/<skill>/fixture/` and executes `test-procedure.md` case by case, reporting pass / fail per case at the end. The procedure is the assertion; the subagent's transcript is the result.

*Do not import these directories from `pytest`; do not gate CI on them.*

## When to edit

Edit `tests/skills/<skill>/test-procedure.md` in the same commit as any source change that renames a skill command, removes a tool, or changes a contract surface the procedure exercises — the procedure is part of the skill's user-visible contract.

*Do not modify a fixture during a run* — that breaks reproducibility for the next subagent.
