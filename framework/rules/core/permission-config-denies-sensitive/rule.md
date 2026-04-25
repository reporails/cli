---
id: CORE:G:0005
slug: permission-config-denies-sensitive
title: Permission Config Denies Sensitive
category: governance
type: mechanical
severity: medium
backed_by: []
match: {type: config}
source: https://code.claude.com/docs/en/settings
---
# Permission Config Denies Sensitive

Configuration files must contain at least one constraint instruction that restricts access to sensitive files. Without an explicit denial, the agent may read or write secrets, credentials, and private keys.

## Antipatterns

- **Config file with only positive directives.** A settings file that grants permissions but never denies anything fails -- the check requires at least one constraint atom (a `-1` charge instruction such as "NEVER read `.env` files").
- **Mentioning sensitive files in prose without a constraint.** Describing that `.env` files exist is not a denial. The check looks for constraint-charged instructions, not informational references.
- **Relying on `.gitignore` alone.** Excluding sensitive files from version control does not prevent the agent from reading them at runtime. The config must contain an explicit denial instruction.

## Pass / Fail

### Pass

~~~~markdown
# Sensitive Files

Ask the user to modify `.env`, `.env.*`, `credentials*`, and `*.pem` files manually.
*Do NOT read or write these files.*
~~~~

### Fail

~~~~markdown
# Project Settings

This project uses `.env` for environment variables.
See `credentials.json` for API keys.
~~~~

## Limitations

Checks for at least one constraint atom restricting access to secrets or credentials. Does not verify the restrictions match the project's actual sensitive files.
