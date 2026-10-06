---
id: CORE:G:0002
slug: no-credentials
title: No Credentials
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: ci
severity: medium
backed_by: [advanced-context-engineering, agent-readmes-empirical-study, dometrain-claude-md-guide,
  openai-community-agents-md-optimization, spec-writing-for-agents]
match: {format: [freeform, frontmatter, schema_validated]}
---

# No Credentials

Instruction files must never contain credentials, API keys, or private keys. Secrets in instruction files get committed to version control.

The check reports every line that holds a secret, in prose and in code blocks, in the file you wrote and in any file it imports with `@path` (the finding names the imported file and its line). It reports:

- a `password`, `api_key` or `secret_key` assigned a literal value, with `=` or `:`
- a well-known key written anywhere in a line: an `sk-` API key (`sk-live-…`, `sk-proj-…`, `sk-ant-…`), a GitHub token (`ghp_…`, `github_pat_…`), an AWS access key id (`AKIA…`), a Slack token (`xoxb-…`)
- a private key or certificate header (`-----BEGIN RSA PRIVATE KEY-----`)

A reference to a secret is not a secret. The check reports a literal value and leaves these alone: an environment-variable reference (`$NAME`, `${NAME}`, `%NAME%`, `{{ name }}`), an angle-bracket or all-caps placeholder (`<ask the lead>`, `YOUR_PASSWORD`), emphasis (`*ever*`), a YAML block marker (`|`, `>`), and a parameter or field declared with a type and no value (`password: string`, `password?: str`, `String password`). A key shape followed by a placeholder word (`sk-live-<your-key>`, `xoxb-your-token`) or written as `sk-...` is not reported.

## Antipatterns

- Embedding an example API key like `api_key = "sk-abc123"` in a code block -- the check scans all content including fenced code blocks for credential patterns.
- Including a `password: mypass` line as a configuration example -- the check flags `password`, `api_key` and `secret_key` followed by `=` or `:` and a literal value, including a value that starts with a symbol.
- Pasting a PEM certificate block (`-----BEGIN PRIVATE KEY-----`) for reference -- the check flags private key and certificate headers regardless of context.

## Pass / Fail

### Pass

~~~~markdown
## Authentication

Set `API_KEY` in your `.env` file (not tracked by git).
Use `$DATABASE_PASSWORD` environment variable for DB access.
~~~~

### Fail

~~~~markdown
## Authentication

api_key = "sk-live-abc123def456"
password: "hunter2"
-----BEGIN RSA PRIVATE KEY-----
~~~~

## Limitations

Uses pattern matching to detect common credential formats (passwords, API keys, private key headers). May miss custom credential patterns or obfuscated values.
