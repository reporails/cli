---
id: CORE:S:0009
slug: valid-markdown-syntax
title: Valid Markdown Syntax
category: structure
type: mechanical
severity: critical
backed_by: [agentic-coding-adoption-github]
match: {format: freeform}
---
# Valid Markdown Syntax

Instruction files must contain valid markdown structure. Broken or empty markdown prevents agents from parsing content correctly and can cause instructions to be silently ignored.

## Antipatterns

- Leaving unclosed fenced code blocks (starting ``` without a closing ```). The parser treats everything after the opening fence as code, hiding subsequent instructions.
- Creating a file with only frontmatter and no body content. An empty body produces no valid markdown structure for the agent to parse.
- Using malformed heading syntax (`##No space after hashes`). Missing the space after `#` characters prevents heading detection.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

Use `uv sync` to install dependencies.

```bash
uv run pytest tests/
```
~~~~

### Fail

~~~~markdown
---
title: Project
---
~~~~

## Limitations

Checks that the file parses into at least one content atom. Catches empty files and files with only frontmatter, but does not detect all structural issues — an unclosed code block that still produces some atoms before the fence would pass.
