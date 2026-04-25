---
id: CORE:C:0024
slug: domain-terminology-used
title: Domain Terminology Used
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, developer-context-cursor-study, dometrain-claude-md-guide,
  sewell-agents-md-tips, spec-writing-for-agents]
match: {type: main}
---
# Domain Terminology Used

Instruction files must include a section with a heading matching "Terminology", "Glossary", "Terms", or "Domain" that defines project-specific vocabulary. Defining terms prevents the agent from misinterpreting domain-specific words that have different common meanings.

## Antipatterns

- **Using domain terms without defining them** like referencing "backbone" or "atom" throughout the file without a glossary section — the check looks for a heading that signals term definitions, not inline usage.
- **Generic heading that skips the keywords** like `## Definitions` or `## Vocabulary` — the check matches only "Terminology", "Glossary", "Terms", or "Domain" in headings.
- **Terms defined in a separate file** with no matching heading in the instruction file — the content query scans only the matched file.

## Pass / Fail

### Pass

~~~~markdown
## Terminology
- **atom**: a single parsed instruction sentence
- **backbone**: the project topology file
- **charge**: directive (+1) or constraint (-1) classification
~~~~

### Fail

~~~~markdown
## Conventions
Use atoms when building rulesets.
Reference the backbone for project structure.
~~~~

## Limitations

Checks for a heading containing "Terminology", "Glossary", "Terms", or "Domain". Does not verify the section defines project-specific terms.
