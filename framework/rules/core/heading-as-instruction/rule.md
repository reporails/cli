---
id: CORE:S:0039
slug: heading-as-instruction
title: "Heading As Instruction"
category: structure
type: mechanical
severity: medium
surface_mutations:
  config: {applies: false}
---

# Heading As Instruction

Headings should organize content into sections, not carry instructions. The model processes heading content the same as body content, but instructions in headings are structurally fragile — they get lost when files are reorganized, and they can't carry the detail an instruction needs.

A bare negative heading such as `## Don'ts`, `## Never` or `## Must Not` is the exception and is not reported: it labels a list of prohibitions, and the items under it read as things not to do. Keep such a heading and its list together.

## Antipatterns

- **Imperative verb in a heading**: `## Always Run Tests Before Pushing` — this is an instruction disguised as a section label. The check classifies the heading itself as a directive or an imperative.
- **Constraint as heading**: `## Never Modify Generated Files` — constraints belong in the section body, not the heading. The heading should name the topic (e.g., `## Generated Files`).
- **Multi-clause heading**: `## Use ruff and Do Not Run black` — packing both a directive and a constraint into a heading makes both structurally fragile and undetectable by checks that scan body content.

## Pass / Fail

### Pass

~~~~markdown
## Deployment

Never push directly to main. Use feature branches and open a pull request.
~~~~

### Fail

~~~~markdown
## Never Push Directly to Main

Use feature branches and open a pull request instead.
~~~~

## Limitations

Detects headings classified as directive, imperative, or constraint. It also fires on headings that open with a verb but name a section: a procedure's step titles (`### Step 2: Evaluate each check entry`), a skill's title (`# Write Rule`), and short labels read as commands (`## Approach`). The check cannot tell a heading that is the only statement of an instruction from one that names a section whose body carries it.
