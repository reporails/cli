---
id: CLAUDE:S:0009
slug: rule-snippet-length
title: Rule File Length Limit
category: structure
type: mechanical
severity: low
match: {type: scoped_rule}
see_also: [CORE:C:0044, CORE:S:0019]
source: https://code.claude.com/docs/en/memory#organize-rules-with-clauderules
---

# Rule File Length Limit

Keep `.claude/rules/*.md` files under 200 lines. This is best-practice guidance rather than a documented Claude Code limit — Claude Code does not truncate rule files at any length. The 200-line ceiling is a soft cap that works in concert with the topic-focus rules: when a rule file follows `CORE:C:0044 topic-scatter` (one or two topics per file) and `CORE:S:0019 single-topic-per-section` (each topic in its own section), 200 lines is comfortably enough to cover that scope with concrete examples and constraints. Files that exceed the cap usually betray topic fragmentation, redundant restatement, or examples that belong in referenced project files rather than inline. Long rule files also compete for attention with other context — every line is loaded into the agent's context window at session start, so density wins over breadth.

## Antipatterns

- **Mega-rule file.** Putting testing conventions, formatting rules, and deployment procedures into a single `.claude/rules/guidelines.md`. The file exceeds 200 lines and dilutes every instruction across topics.
- **Inline examples that belong in code.** Embedding 30+ lines of example code inside a rule file instead of referencing the project's existing files or test fixtures.
- **Redundant restatement.** Rephrasing the same instruction multiple ways ("Use ruff. Always format with ruff. Make sure to run ruff.") to fill out the file rather than stating it once with specificity.

## Pass / Fail

### Pass

~~~~markdown
---
description: Testing conventions
---
# Testing

Run `uv run pytest tests/ -v` before committing.
Use `@pytest.mark.parametrize` for multi-case tests.
*Do NOT mock database connections — use the test fixture in `conftest.py`.*
~~~~

### Fail

~~~~markdown
---
description: Project guidelines
---
# Guidelines

## Testing
Run pytest before committing...
## Formatting
Use ruff for formatting...
## Deployment
Deploy with docker compose...
## Security
Never commit secrets...
## Git
Always create feature branches...
[... 220+ lines covering 6 topics — split into one-topic-per-file]
~~~~

## Limitations

Counts total lines including frontmatter, headings, and blank lines. Files just over the threshold may be acceptable when the content is dense and focused on a single topic — this rule is a best-practice signal, not a Claude Code-enforced cap.
