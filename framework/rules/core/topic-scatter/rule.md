---
id: CORE:C:0044
slug: topic-scatter
title: "Topic Scatter"
category: coherence
type: mechanical
execution: server
severity: critical
match: {}
---

# Topic Scatter

Instruction files must focus on 1-2 topics. Instructions spanning multiple unrelated topics compete for attention, degrading compliance on all topics -- while same-topic instructions reinforce each other.

## Antipatterns

- Putting testing instructions, deployment steps, formatting rules, and security constraints all in one scoped rule file. Each unrelated topic reduces compliance on every other topic.
- Adding "one more thing" to an existing file rather than creating a new file. Incremental topic additions cause gradual scatter that is hard to notice.
- Using a single `.claude/rules/everything.md` file instead of splitting into focused files like `testing.md`, `formatting.md`, and `security.md`.

## Pass / Fail

### Pass

~~~~markdown
<!-- .claude/rules/testing.md -->
# Testing
Run `uv run pytest tests/ -v` before committing.
Use `@pytest.mark.parametrize` for multi-case tests.
~~~~

### Fail

~~~~markdown
<!-- .claude/rules/guidelines.md -->
# Guidelines
Run pytest before committing. Use ruff for formatting.
NEVER push to main. Deploy with docker compose up.
~~~~

## Fix

Keep instruction files to 1-2 topics maximum. As topic count grows, individual instruction compliance drops sharply. Split multi-topic files into single-topic files. For critical directives, add same-topic reinforcement.

## Limitations

Counts competing topics using embedding-based clustering. Intentionally broad files (like a main `CLAUDE.md` that covers multiple concerns) will be flagged — the diagnostic applies to all files equally.
