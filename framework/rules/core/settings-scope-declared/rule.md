---
id: CORE:S:0021
slug: settings-scope-declared
title: Settings Scope Declared
category: structure
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage]
match: {type: config}
---
# Settings Scope Declared

Configuration files must contain a heading matching scope-related terms (Settings, Scope, or Configuration). Declaring scope level ensures the agent knows whether settings apply project-wide, per-user, or are system-managed.

## Antipatterns

- Embedding scope information in comments or inline text without a heading. The check requires a heading containing Settings, Scope, or Configuration.
- Using a heading like "Options" or "Preferences" that describes configuration content but does not match the expected terms.
- Assuming scope is implied by the file's location. The check requires an explicit heading declaration regardless of where the file lives.

## Pass / Fail

### Pass

~~~~markdown
# Agent Config

## Settings

scope: project
format: yaml
~~~~

### Fail

~~~~markdown
# Agent Config

format: yaml
version: 1.0
~~~~

## Limitations

Checks for a heading containing "Settings", "Scope", or "Configuration". Does not verify the content under that heading actually declares a scope level — only that the heading exists.
