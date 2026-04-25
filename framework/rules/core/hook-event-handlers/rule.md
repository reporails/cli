---
id: CORE:S:0020
slug: hook-event-handlers
title: Hook Event Handlers
category: structure
type: mechanical
severity: medium
backed_by: [enterprise-claude-usage, fowler-context-engineering-agents, instruction-limits-principles]
match: {type: config}
---
# Hook Event Handlers

Config files that define hooks or event handlers must include a heading matching Hook, Event, Trigger, or Pre-commit. Without a labeled section, trigger conditions are buried in unstructured content where they are easy to miss.

## Antipatterns

- **Hook logic without a labeled section**: Describing pre-commit behavior in a general "Workflow" section without a heading containing "Hook", "Event", "Trigger", or "Pre-commit". The check looks for headings matching those keywords.
- **Trigger keyword only in body text**: Mentioning "trigger" or "hook" in paragraphs but never in a heading. The check requires a heading-level match, not body-level.
- **Generic heading name**: Using `## Automation` to describe event handlers instead of `## Event Handlers` or `## Pre-commit Hooks`. The heading must contain one of the target keywords.

## Pass / Fail

### Pass

~~~~markdown
## Pre-commit Hooks

Run `ruff check` and `pytest` before each commit.
~~~~

### Fail

~~~~markdown
## Workflow

Before committing, the linter runs automatically.
~~~~

## Limitations

Checks for a heading containing "Hook", "Event", "Trigger", or "Pre-commit". Does not verify the section documents actual event handler configurations.
