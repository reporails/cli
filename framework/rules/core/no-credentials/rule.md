---
id: CORE:G:0002
slug: no-credentials
title: "No Credentials"
category: governance
type: deterministic
severity: medium
backed_by: []
match: {format: [freeform, frontmatter, schema_validated]}
---

# No Credentials

Instruction files must never contain credentials, API keys, or private keys. Secrets in instruction files get committed to version control.

## Antipatterns

- Embedding an example API key like `api_key = "sk-abc123"` in a code block -- the check scans all content including fenced code blocks for credential patterns.
- Including a `password: mypass` line as a configuration example -- the pattern matches `password` followed by `=` or `:` and a value.
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
