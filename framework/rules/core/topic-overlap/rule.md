---
id: CORE:C:0044
slug: topic-overlap
title: "Topic Overlap Across Elements"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
---

# Topic Overlap Across Elements

Give each topic one home. When two instruction files that can load in the same session both carry instructions on the same topic, the project has two sources of truth for it. The copies drift apart as one is edited and the other is not, and the agent then reads guidance that disagrees with itself. Keep the shared instructions in the file that owns the topic, and point to them from the other.

## Antipatterns

- Restating the testing workflow in `CLAUDE.md`, in `.claude/rules/testing.md`, and in a `qa` skill. Three copies of one topic mean three places to update, and the first missed edit leaves them contradicting each other.
- Copying a convention list into two skills that are often used in the same session, instead of keeping it in one skill and referencing it from the other.
- Letting a memory note restate, in slightly different words, an instruction the main instruction file already carries.

## Pass / Fail

### Pass

~~~~markdown
<!-- CLAUDE.md -->
Run `uv run poe qa` before committing. Testing conventions: see `.claude/rules/testing.md`.

<!-- .claude/rules/testing.md -->
Use `pytest` fixtures from `conftest.py` for shared setup.
Mark slow tests with `@pytest.mark.slow`.
~~~~

### Fail

~~~~markdown
<!-- CLAUDE.md -->
Run `pytest -x` to stop at the first failing test.
Put shared test setup in `tests/conftest.py` fixtures.

<!-- .claude/rules/testing.md -->
Run `pytest -x -q` to stop at the first failing test.
Put shared test setup in `tests/fixtures.py` helpers.
~~~~

## Limitations

Reports a pair of files that can load together when a substantial share of their instructions have a same-topic, same-direction counterpart in the other file. Instructions on one topic that point in opposite directions are a conflict, not an overlap, and are not reported here. Skill and agent descriptions are not compared. A subagent definition pairs only with files loaded at session start: a subagent runs in its own context, which loads those but no skill, command, or other subagent definition.
