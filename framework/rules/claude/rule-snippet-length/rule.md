---
id: CLAUDE:S:0009
slug: rule-snippet-length
title: Rule File Length Limit
category: structure
type: mechanical
severity: medium
match: {type: scoped_rule}
source: https://code.claude.com/docs/en/memory#organize-rules-with-clauderules
---

# Rule File Length Limit

Keep `.claude/rules/*.md` files under 100 lines. Long rule files compete for attention with other context — every line in a rule file is loaded into the agent's context window at session start. Each rule file should address one topic with focused instructions.

## Antipatterns

- **Mega-rule file.** Putting testing conventions, formatting rules, and deployment procedures into a single `.claude/rules/guidelines.md`. The file exceeds 100 lines and dilutes every instruction.
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
[... 120+ lines covering 6 topics]
~~~~

## Limitations

Counts total lines including frontmatter, headings, and blank lines. Files just over the threshold may be acceptable if the content is dense and focused on a single topic.
