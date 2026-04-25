---
id: CORE:G:0007
slug: project-config-self-contained
title: Project Config Self Contained
category: governance
type: deterministic
severity: medium
backed_by: []
match: {type: main}
source: https://code.claude.com/docs/en/settings
---
# Project Config Self Contained

Project configuration must be self-contained — no dependencies on user-specific setup or external state not documented in the project.

## Antipatterns

- **Referencing home directory paths.** Instructions containing `~/` or `$HOME` depend on the user's local filesystem layout. Different contributors have different home directories, breaking reproducibility.
- **Requiring undocumented tool installation.** Phrases like "requires installing X" or "install the plugin first" indicate an external dependency that is not bundled or pinned in the project configuration.
- **Using environment variable references.** Writing "set the `env var` for the API key" makes the instruction depend on external state that may not exist on another machine.

## Pass / Fail

### Pass

~~~~markdown
# Setup

Run `uv sync` to install dependencies.
Use `uv run ails check .` to validate instruction files.
~~~~

### Fail

~~~~markdown
# Setup

Run `~/bin/custom-tool check` to validate files.
Set the env var `API_KEY` before running.
Requires installing the reporails plugin globally.
~~~~

## Limitations

Detects references to external dependencies (`~/`, `$HOME`, `env var`, `requires install`). May miss indirect or obfuscated external references.
