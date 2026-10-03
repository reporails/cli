---
id: CORE:C:0024
slug: domain-terminology-used
title: Domain Terminology Used
category: coherence
type: mechanical
severity: medium
backed_by: [agent-readmes-empirical-study, developer-context-cursor-study, dometrain-claude-md-guide,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Domain Terminology Used

Instruction files must include a section with a heading matching "Terminology", "Glossary", "Terms", or "Domain" that defines project-specific vocabulary. Defining terms prevents the agent from misinterpreting domain-specific words that have different common meanings.

## Antipatterns

- **Using domain terms without defining them** like referencing "tenant" or "webhook" throughout the file without a glossary section — the check looks for a heading that signals term definitions, not inline usage.
- **Generic heading that skips the keywords** like `## Definitions` or `## Vocabulary` — the check matches only "Terminology", "Glossary", "Terms", or "Domain" in headings.
- **Terms defined in a separate file** with no matching heading in the instruction file — the content query scans only the matched file.

## Pass / Fail

### Pass

~~~~markdown
## Terminology
- **tenant**: an isolated customer workspace
- **ledger**: the append-only transaction log
- **webhook**: an outbound event notification
~~~~

### Fail

~~~~markdown
## Conventions
Use tenants when scoping a request.
Reference the ledger for transaction history.
~~~~

## Limitations

Checks for a heading containing "Terminology", "Glossary", "Terms", or "Domain". Does not verify the section defines project-specific terms.
